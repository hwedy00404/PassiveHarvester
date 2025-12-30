# -*- coding: utf-8 -*-
# Advanced Passive Harvester - Professional Edition
# Enhanced by Hwedy00 - Web Application Security Expert
# Fully compatible with Burp Suite + Jython

from burp import IBurpExtender, IScannerCheck, IHttpListener, ITab, IScanIssue
from java.io import PrintWriter, FileWriter
from java.util import ArrayList, List, Set, HashSet
from java.awt import Font, Color, BorderLayout, GridLayout, Dimension
from javax import swing
from java.lang import String, Runnable
from javax.swing import JFileChooser, SwingUtilities
import re
import json
import time
from datetime import datetime

# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================
MAX_BODY_SIZE = 2 * 1024 * 1024  # 2MB limit for performance
REGEX_TIMEOUT = 2  # seconds
MIN_PARAM_LENGTH = 3
MAX_PARAM_LENGTH = 50
SCORE_THRESHOLD_HIGH = 70
SCORE_THRESHOLD_MEDIUM = 40

# Comprehensive boring words list
BORING_WORDS = {
    # HTML/CSS Common
    'div', 'span', 'container', 'wrapper', 'row', 'col', 'content', 'main',
    'header', 'footer', 'sidebar', 'navbar', 'menu', 'item', 'list', 'grid',
    'section', 'article', 'aside', 'figure', 'caption', 'label', 'button',
    'input', 'form', 'table', 'thead', 'tbody', 'tfoot', 'dialog', 'modal',
    
    # CSS Properties
    'color', 'width', 'height', 'margin', 'padding', 'display', 'position',
    'border', 'background', 'font', 'text', 'align', 'flex', 'grid',
    
    # JavaScript Common
    'function', 'const', 'let', 'var', 'return', 'if', 'else', 'for', 'while',
    'switch', 'case', 'break', 'continue', 'true', 'false', 'null', 'undefined',
    'this', 'self', 'window', 'document', 'console', 'length', 'index',
    
    # Frameworks/Libraries
    'react', 'vue', 'angular', 'jquery', 'bootstrap', 'material', 'semantic',
    'component', 'props', 'state', 'render', 'mount', 'hook', 'ref',
    
    # Generic Words
    'the', 'a', 'an', 'of', 'in', 'is', 'for', 'to', 'and', 'or', 'not',
    'url', 'href', 'link', 'src', 'alt', 'title', 'class', 'style', 'type',
    'name', 'value', 'data', 'info', 'get', 'set', 'has', 'add', 'remove'
}

# JavaScript exclusion list for libraries
JS_EXCLUSION_LIST = [
    'jquery', 'google-analytics', 'gtm', 'adsbygoogle', 'bootstrap', 
    'fontawesome', 'cdn', 'cloudflare', 'jsdelivr', 'unpkg', 'analytics'
]


# ============================================================================
# PARAMETER DATA CLASS
# ============================================================================
class ParameterFinding:
    """Enhanced parameter finding with context and scoring"""
    
    def __init__(self, param_name, source_type, url, sample_value=None):
        self.param = param_name
        self.source_type = source_type  # 'html_attr', 'json_key', 'js_var', 'post_param', 'header', 'url_param'
        self.url = url
        self.sample_value = sample_value
        self.timestamp = time.time()
        self.score = 0
        self.mutations = set()
        
    def calculate_score(self):
        """Calculate parameter importance score"""
        score = 0
        param_lower = self.param.lower()
        
        # Critical identifiers (IDOR potential)
        if any(x in param_lower for x in ['_id', 'userid', 'user_id', 'uid', 'accountid']):
            score += 50
            
        # Authentication/Authorization
        if any(x in param_lower for x in ['token', 'auth', 'key', 'secret', 'session', 'jwt', 'bearer']):
            score += 60
            
        # Admin/privileged access
        if any(x in param_lower for x in ['admin', 'role', 'privilege', 'permission', 'access']):
            score += 55
            
        # Reflection points (XSS potential)
        if any(x in param_lower for x in ['search', 'query', 'q', 'input', 'msg', 'message', 'comment', 'text']):
            score += 45
            
        # File operations (LFI/RFI potential)
        if any(x in param_lower for x in ['file', 'path', 'dir', 'folder', 'upload', 'download', 'include']):
            score += 50
            
        # Database operations (SQLi potential)
        if any(x in param_lower for x in ['sql', 'query', 'select', 'where', 'table', 'db', 'database']):
            score += 55
            
        # Redirect/SSRF potential
        if any(x in param_lower for x in ['url', 'redirect', 'next', 'return', 'callback', 'continue', 'dest']):
            score += 45
            
        # Command execution
        if any(x in param_lower for x in ['cmd', 'command', 'exec', 'run', 'shell', 'bash']):
            score += 65
            
        # Email/Contact
        if any(x in param_lower for x in ['email', 'mail', 'contact', 'phone', 'address']):
            score += 30
            
        # Hidden/Undocumented (found in JS but not in HTML)
        if self.source_type == 'js_var':
            score += 20
            
        # JSON keys are more reliable than HTML attributes
        if self.source_type == 'json_key':
            score += 15
            
        self.score = min(score, 100)  # Cap at 100
        return self.score
    
    def generate_mutations(self):
        """Generate parameter mutations for fuzzing"""
        mutations = set()
        param = self.param
        
        # Case variations
        mutations.add(param.upper())
        mutations.add(param.lower())
        mutations.add(param.capitalize())
        
        # Delimiter variations
        mutations.add(param.replace('_', '-'))
        mutations.add(param.replace('-', '_'))
        mutations.add(param.replace('_', ''))
        mutations.add(param.replace('-', ''))
        
        # Array notations
        mutations.add(param + '[]')
        mutations.add(param + '[0]')
        mutations.add(param + '[1]')
        
        # CamelCase variations
        if '_' in param or '-' in param:
            parts = param.replace('-', '_').split('_')
            # PascalCase
            pascal = ''.join(p.capitalize() for p in parts)
            mutations.add(pascal)
            # camelCase
            camel = parts[0] + ''.join(p.capitalize() for p in parts[1:])
            mutations.add(camel)
        
        # Prefix/Suffix common patterns
        mutations.add('x-' + param)
        mutations.add(param + '_param')
        mutations.add(param + 'Id')
        mutations.add(param + 'ID')
        
        self.mutations = mutations
        return mutations
    
    def to_dict(self):
        """Convert to dictionary for JSON export"""
        return {
            'parameter': self.param,
            'source_type': self.source_type,
            'url': self.url,
            'sample_value': self.sample_value,
            'score': self.score,
            'mutations': list(self.mutations),
            'timestamp': self.timestamp
        }


# ============================================================================
# PASSIVE HARVESTER LOGIC (CORE ENGINE)
# ============================================================================
class PassiveHarvesterLogic:
    """Enhanced passive harvesting engine with advanced pattern recognition"""
    
    def __init__(self):
        self.findings = []  # List of ParameterFinding objects
        self.unique_params = HashSet()  # For quick lookup
        self.boring_words = BORING_WORDS
        self.stats = {
            'total_scanned': 0,
            'params_found': 0,
            'high_value': 0,
            'medium_value': 0,
            'low_value': 0
        }
    
    def get_findings(self):
        """Return all findings"""
        return self.findings
    
    def get_unique_params(self):
        """Return unique parameter names"""
        return self.unique_params
    
    def _is_valid_param(self, param_name):
        """Validate parameter name"""
        if param_name is None or not param_name:
            return False
        
        # Convert to string if needed
        if isinstance(param_name, String):
            param = str(param_name).strip()
        else:
            param = str(param_name).strip()
        
        # Length check
        if len(param) < MIN_PARAM_LENGTH or len(param) > MAX_PARAM_LENGTH:
            return False
        
        # Must contain at least one letter
        if not re.search(r'[a-zA-Z]', param):
            return False
        
        # Check against boring words
        param_lower = param.lower().replace('-', '_')
        if param_lower in self.boring_words:
            return False
        
        # Valid characters only
        if not re.match(r'^[a-zA-Z0-9_-]+$', param):
            return False
        
        return True
    
    def _add_finding(self, param_name, source_type, url, sample_value=None):
        """Add a parameter finding with deduplication"""
        if not self._is_valid_param(param_name):
            return False
        
        # Normalize parameter name
        param_normalized = param_name.strip().lower().replace('-', '_')
        
        # Create unique key for deduplication
        unique_key = param_normalized + "|" + source_type
        
        if not self.unique_params.contains(unique_key):
            self.unique_params.add(unique_key)
            
            finding = ParameterFinding(param_normalized, source_type, url, sample_value)
            finding.calculate_score()
            finding.generate_mutations()
            
            self.findings.append(finding)
            self.stats['params_found'] += 1
            
            # Update stats by score
            if finding.score >= SCORE_THRESHOLD_HIGH:
                self.stats['high_value'] += 1
            elif finding.score >= SCORE_THRESHOLD_MEDIUM:
                self.stats['medium_value'] += 1
            else:
                self.stats['low_value'] += 1
            
            return True
        
        return False
    
    def harvest_from_url(self, url_str):
        """Extract parameters from URL query string"""
        if not url_str or '?' not in url_str:
            return
        
        try:
            query_string = url_str.split('?', 1)[1]
            if '&' in query_string or '=' in query_string:
                for param_pair in query_string.split('&'):
                    if '=' in param_pair:
                        param_name = param_pair.split('=', 1)[0]
                        param_value = param_pair.split('=', 1)[1] if len(param_pair.split('=')) > 1 else None
                        self._add_finding(param_name, 'url_param', url_str, param_value)
        except Exception as e:
            pass  # Silently fail on malformed URLs
    
    def harvest_from_html(self, html_content, url):
        """Extract parameters from HTML with enhanced patterns"""
        if not html_content:
            return
        
        content = str(html_content)
        
        # Limit size for performance
        if len(content) > MAX_BODY_SIZE:
            content = content[:MAX_BODY_SIZE]
        
        try:
            # 1. Form input names and IDs
            for match in re.findall(r'<input[^>]*\s+(?:name|id)\s*=\s*["\']?([a-zA-Z0-9_-]+)', content, re.IGNORECASE):
                self._add_finding(match, 'html_attr', url)
            
            # 2. Other form elements (select, textarea)
            for match in re.findall(r'<(?:select|textarea)[^>]*\s+name\s*=\s*["\']?([a-zA-Z0-9_-]+)', content, re.IGNORECASE):
                self._add_finding(match, 'html_attr', url)
            
            # 3. data-* attributes (API parameters often leaked here)
            for match in re.findall(r'data-([a-zA-Z0-9_-]+)\s*=', content, re.IGNORECASE):
                self._add_finding(match, 'html_attr', url)
            
            # 4. URLs in href, action, formaction, src
            for attr in ['href', 'action', 'formaction', 'src']:
                pattern = r'%s\s*=\s*["\']?([^"\'>\s]+)' % attr
                for url_val in re.findall(pattern, content, re.IGNORECASE):
                    if '?' in url_val:
                        self.harvest_from_url(url_val)
            
            # 5. Hidden inputs (often contain tokens/IDs)
            for match in re.findall(r'<input[^>]*type\s*=\s*["\']?hidden[^>]*name\s*=\s*["\']?([a-zA-Z0-9_-]+)', content, re.IGNORECASE):
                self._add_finding(match, 'html_attr', url)
            
        except Exception as e:
            pass
    
    def harvest_from_javascript(self, js_content, url):
        """Enhanced JavaScript parameter extraction"""
        if not js_content:
            return
        
        content = str(js_content)
        
        # Limit size
        if len(content) > MAX_BODY_SIZE:
            content = content[:MAX_BODY_SIZE]
        
        try:
            # 1. Object properties: { key: value }
            for match in re.findall(r'["\']([a-zA-Z0-9_-]+)["\']\s*:', content):
                self._add_finding(match, 'json_key', url)
            
            # 2. Variable declarations: const/let/var name
            for match in re.findall(r'(?:const|let|var)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*=', content):
                self._add_finding(match, 'js_var', url)
            
            # 3. Destructuring: const {param1, param2} = obj
            for match in re.findall(r'(?:const|let|var)\s+\{([^}]+)\}', content):
                for param in match.split(','):
                    param_clean = param.split(':')[0].strip()
                    if param_clean:
                        self._add_finding(param_clean, 'js_var', url)
            
            # 4. Function parameters: function name(param1, param2)
            for func_sig in re.findall(r'function\s+\w+\s*\(([^)]*)\)', content):
                for param in func_sig.split(','):
                    param_clean = param.strip().split('=')[0].strip()
                    if param_clean:
                        self._add_finding(param_clean, 'js_var', url)
            
            # 5. Arrow functions: (param1, param2) =>
            for func_sig in re.findall(r'\(([^)]*)\)\s*=>', content):
                for param in func_sig.split(','):
                    param_clean = param.strip().split('=')[0].strip()
                    if param_clean:
                        self._add_finding(param_clean, 'js_var', url)
            
            # 6. API endpoints in fetch/axios/ajax
            for match in re.findall(r'(?:fetch|axios|ajax|get|post)\s*\(\s*["\']([^"\']+)', content, re.IGNORECASE):
                if '?' in match:
                    self.harvest_from_url(match)
            
            # 7. Object property access: obj.property
            for match in re.findall(r'\.([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:[=\(]|\s|$)', content):
                self._add_finding(match, 'js_var', url)
            
            # 8. URLSearchParams usage
            for match in re.findall(r'\.(?:set|append|get)\s*\(\s*["\']([a-zA-Z0-9_-]+)', content):
                self._add_finding(match, 'url_param', url)
            
        except Exception as e:
            pass
    
    def harvest_from_json(self, json_content, url):
        """Extract parameters from JSON responses"""
        if not json_content:
            return
        
        content = str(json_content)
        
        if len(content) > MAX_BODY_SIZE:
            content = content[:MAX_BODY_SIZE]
        
        try:
            # Try to parse as JSON first
            try:
                data = json.loads(content)
                self._extract_json_keys(data, url)
            except:
                # Fallback to regex if JSON parsing fails
                for match in re.findall(r'["\']([a-zA-Z0-9_-]+)["\']\s*:', content):
                    self._add_finding(match, 'json_key', url)
        except Exception as e:
            pass
    
    def _extract_json_keys(self, obj, url, depth=0):
        """Recursively extract keys from JSON object"""
        if depth > 5:  # Limit recursion depth
            return
        
        try:
            if isinstance(obj, dict):
                for key in obj.keys():
                    self._add_finding(str(key), 'json_key', url)
                    self._extract_json_keys(obj[key], url, depth + 1)
            elif isinstance(obj, list):
                for item in obj[:10]:  # Limit array items
                    self._extract_json_keys(item, url, depth + 1)
        except:
            pass
    
    def harvest_from_headers(self, headers_list, url):
        """Extract interesting header names"""
        if not headers_list:
            return
        
        for header_line in headers_list:
            if not header_line or ':' not in header_line:
                continue
            
            try:
                name = header_line.split(':', 1)[0].strip()
                name_lower = name.lower()
                
                # Custom headers (X-*, API-*)
                if name_lower.startswith('x-') or name_lower.startswith('api-'):
                    param_name = name.replace('-', '_')
                    self._add_finding(param_name, 'header', url)
                
                # Authentication headers
                elif any(x in name_lower for x in ['token', 'auth', 'key', 'session']):
                    param_name = name.replace('-', '_')
                    self._add_finding(param_name, 'header', url)
                
            except Exception as e:
                pass
    
    def get_high_value_findings(self):
        """Return findings with high scores"""
        return [f for f in self.findings if f.score >= SCORE_THRESHOLD_HIGH]
    
    def get_statistics(self):
        """Return harvesting statistics"""
        return self.stats


# ============================================================================
# BURP EXTENDER IMPLEMENTATION
# ============================================================================
class BurpExtender(IBurpExtender, IScannerCheck, IHttpListener, ITab):
    
    def registerExtenderCallbacks(self, callbacks):
        self.callbacks = callbacks
        self.helpers = callbacks.getHelpers()
        self.harvester = PassiveHarvesterLogic()
        
        callbacks.setExtensionName("Advanced Passive Harvester")
        self.stdout = PrintWriter(callbacks.getStdout(), True)
        self.stderr = PrintWriter(callbacks.getStderr(), True)
        
        callbacks.registerScannerCheck(self)
        callbacks.registerHttpListener(self)
        self.initUI()
        callbacks.addSuiteTab(self)
        
        self.stdout.println("=" * 60)
        self.stdout.println("Advanced Passive Harvester - Professional Edition")
        self.stdout.println("Enhanced by Hwedy00 - Web Security Expert")
        self.stdout.println("=" * 60)
        self.stdout.println("[+] Extension loaded successfully")
        self.stdout.println("[+] Ready to harvest parameters from all in-scope traffic")
        self.stdout.println("")
    
    def initUI(self):
        """Initialize the UI with enhanced layout"""
        self.tab = swing.JPanel(BorderLayout())
        
        # Top panel for title and stats
        topPanel = swing.JPanel(GridLayout(2, 1))
        
        # Title
        titleLabel = swing.JLabel("Advanced Passive Harvester - Professional Edition")
        titleLabel.setFont(Font("Tahoma", Font.BOLD, 16))
        titleLabel.setForeground(Color(255, 102, 52))
        topPanel.add(titleLabel)
        
        # Stats label
        self.statsLabel = swing.JLabel("Stats: 0 total | 0 high value | 0 medium | 0 low")
        self.statsLabel.setFont(Font("Tahoma", Font.PLAIN, 12))
        self.statsLabel.setForeground(Color(100, 100, 100))
        topPanel.add(self.statsLabel)
        
        self.tab.add(topPanel, BorderLayout.NORTH)
        
        # Main text area
        self.outputTxtArea = swing.JTextArea()
        self.outputTxtArea.setFont(Font("Consolas", Font.PLAIN, 12))
        self.outputTxtArea.setLineWrap(False)
        self.outputTxtArea.setEditable(False)
        self.logPane = swing.JScrollPane(self.outputTxtArea)
        self.tab.add(self.logPane, BorderLayout.CENTER)
        
        # Bottom panel for buttons
        buttonPanel = swing.JPanel()
        
        self.clearBtn = swing.JButton("Clear Log", actionPerformed=self.clearLog)
        self.exportTxtBtn = swing.JButton("Export as TXT", actionPerformed=self.exportTxt)
        self.exportJsonBtn = swing.JButton("Export as JSON", actionPerformed=self.exportJson)
        self.showHighValueBtn = swing.JButton("Show High Value Only", actionPerformed=self.showHighValue)
        self.refreshStatsBtn = swing.JButton("Refresh Stats", actionPerformed=self.refreshStats)
        
        buttonPanel.add(self.clearBtn)
        buttonPanel.add(self.exportTxtBtn)
        buttonPanel.add(self.exportJsonBtn)
        buttonPanel.add(self.showHighValueBtn)
        buttonPanel.add(self.refreshStatsBtn)
        
        self.tab.add(buttonPanel, BorderLayout.SOUTH)
        
        # Initial message
        self.outputTxtArea.append("=" * 80 + "\n")
        self.outputTxtArea.append("Advanced Passive Harvester - Ready\n")
        self.outputTxtArea.append("=" * 80 + "\n\n")
        self.outputTxtArea.append("[*] Waiting for in-scope traffic...\n")
        self.outputTxtArea.append("[*] High-value parameters will be highlighted\n\n")
    
    def getTabCaption(self):
        return "Passive Harvester v2"
    
    def getUiComponent(self):
        return self.tab
    
    def clearLog(self, event):
        """Clear the log and reset harvester"""
        self.outputTxtArea.setText("")
        self.outputTxtArea.append("=" * 80 + "\n")
        self.outputTxtArea.append("Log cleared. Harvester reset.\n")
        self.outputTxtArea.append("=" * 80 + "\n\n")
        
        self.harvester = PassiveHarvesterLogic()
        self.updateStats()
    
    def exportTxt(self, event):
        """Export findings as formatted text"""
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Parameters as TXT")
        ret = chooser.showSaveDialog(self.tab)
        
        if ret == JFileChooser.APPROVE_OPTION:
            try:
                file_path = chooser.getSelectedFile().getCanonicalPath()
                if not file_path.endswith('.txt'):
                    file_path += '.txt'
                
                writer = PrintWriter(FileWriter(file_path))
                
                # Write header
                writer.println("=" * 80)
                writer.println("Advanced Passive Harvester - Export Report")
                writer.println("=" * 80)
                writer.println("")
                
                # Write stats
                stats = self.harvester.get_statistics()
                writer.println("Statistics:")
                writer.println("  Total Parameters Found: " + str(stats['params_found']))
                writer.println("  High Value: " + str(stats['high_value']))
                writer.println("  Medium Value: " + str(stats['medium_value']))
                writer.println("  Low Value: " + str(stats['low_value']))
                writer.println("")
                writer.println("=" * 80)
                writer.println("")
                
                # Write findings sorted by score
                findings = sorted(self.harvester.get_findings(), key=lambda x: x.score, reverse=True)
                
                for finding in findings:
                    writer.println("[Score: %d] %s" % (finding.score, finding.param))
                    writer.println("  Source: %s" % finding.source_type)
                    writer.println("  URL: %s" % finding.url)
                    if finding.sample_value:
                        writer.println("  Sample: %s" % finding.sample_value)
                    if finding.mutations:
                        mutations_str = ', '.join(list(finding.mutations)[:5])
                        writer.println("  Mutations: %s..." % mutations_str)
                    writer.println("")
                
                writer.close()
                self.stdout.println("[+] Export completed: " + file_path)
                self.outputTxtArea.append("\n[+] Exported to: " + file_path + "\n")
                
            except Exception as e:
                self.stderr.println("[-] Export error: " + str(e))
    
    def exportJson(self, event):
        """Export findings as JSON"""
        chooser = JFileChooser()
        chooser.setDialogTitle("Export Parameters as JSON")
        ret = chooser.showSaveDialog(self.tab)
        
        if ret == JFileChooser.APPROVE_OPTION:
            try:
                file_path = chooser.getSelectedFile().getCanonicalPath()
                if not file_path.endswith('.json'):
                    file_path += '.json'
                
                # Prepare data
                export_data = {
                    'metadata': {
                        'tool': 'Advanced Passive Harvester',
                        'export_time': str(datetime.now()),
                        'statistics': self.harvester.get_statistics()
                    },
                    'findings': [f.to_dict() for f in self.harvester.get_findings()]
                }
                
                writer = PrintWriter(FileWriter(file_path))
                writer.write(json.dumps(export_data, indent=2))
                writer.close()
                
                self.stdout.println("[+] JSON export completed: " + file_path)
                self.outputTxtArea.append("\n[+] JSON exported to: " + file_path + "\n")
                
            except Exception as e:
                self.stderr.println("[-] JSON export error: " + str(e))
    
    def showHighValue(self, event):
        """Display only high-value parameters"""
        self.outputTxtArea.setText("")
        self.outputTxtArea.append("=" * 80 + "\n")
        self.outputTxtArea.append("HIGH VALUE PARAMETERS (Score >= 70)\n")
        self.outputTxtArea.append("=" * 80 + "\n\n")
        
        high_value = self.harvester.get_high_value_findings()
        
        if not high_value:
            self.outputTxtArea.append("[*] No high-value parameters found yet.\n")
        else:
            for finding in sorted(high_value, key=lambda x: x.score, reverse=True):
                self.outputTxtArea.append("[SCORE: %d] %s\n" % (finding.score, finding.param.upper()))
                self.outputTxtArea.append("  Type: %s\n" % finding.source_type)
                self.outputTxtArea.append("  URL: %s\n" % finding.url)
                if finding.mutations:
                    self.outputTxtArea.append("  Try: %s\n" % ', '.join(list(finding.mutations)[:3]))
                self.outputTxtArea.append("\n")
    
    def refreshStats(self, event):
        """Refresh statistics display"""
        self.updateStats()
        self.outputTxtArea.append("\n[+] Statistics refreshed\n")
    
    def updateStats(self):
        """Update statistics label"""
        stats = self.harvester.get_statistics()
        stats_text = "Stats: %d total | %d high value | %d medium | %d low" % (
            stats['params_found'],
            stats['high_value'],
            stats['medium_value'],
            stats['low_value']
        )
        
        # Thread-safe UI update
        class UpdateStatsRunnable(Runnable):
            def __init__(self, label, text):
                self.label = label
                self.text = text
            
            def run(self):
                self.label.setText(self.text)
        
        SwingUtilities.invokeLater(UpdateStatsRunnable(self.statsLabel, stats_text))
    
    def logParameter(self, finding):
        """Log a parameter finding to the UI"""
        log_msg = ""
        
        # Highlight based on score
        if finding.score >= SCORE_THRESHOLD_HIGH:
            log_msg += "[HIGH SCORE: %d] " % finding.score
            log_msg += ">>> %s <<<\n" % finding.param.upper()
        elif finding.score >= SCORE_THRESHOLD_MEDIUM:
            log_msg += "[MEDIUM SCORE: %d] %s\n" % (finding.score, finding.param)
        else:
            log_msg += "[SCORE: %d] %s\n" % (finding.score, finding.param)
        
        log_msg += "  Source: %s\n" % finding.source_type
        log_msg += "  URL: %s\n" % finding.url[:100]
        
        if finding.sample_value:
            log_msg += "  Sample: %s\n" % str(finding.sample_value)[:50]
        
        if finding.mutations:
            mutations_list = list(finding.mutations)[:3]
            log_msg += "  Mutations: %s\n" % ', '.join(mutations_list)
        
        log_msg += "\n"
        
        # Thread-safe UI update
        class LogRunnable(Runnable):
            def __init__(self, textarea, msg):
                self.textarea = textarea
                self.msg = msg
            
            def run(self):
                self.textarea.append(self.msg)
        
        SwingUtilities.invokeLater(LogRunnable(self.outputTxtArea, log_msg))
    
    # ========================================================================
    # BURP SCANNER CHECK IMPLEMENTATION (PASSIVE SCANNING)
    # ========================================================================
    
    def doPassiveScan(self, baseRequestResponse):
        """Main passive scanning function - called by Burp for each HTTP request/response"""
        try:
            # Only scan in-scope items
            if not self.callbacks.isInScope(baseRequestResponse.getUrl()):
                return None
            
            url = str(baseRequestResponse.getUrl())
            
            # Increment scan counter
            self.harvester.stats['total_scanned'] += 1
            
            # Parse request
            request = baseRequestResponse.getRequest()
            if request:
                analyzedRequest = self.helpers.analyzeRequest(baseRequestResponse)
                
                # 1. Harvest from URL parameters
                self.harvester.harvest_from_url(url)
                
                # 2. Harvest from request headers
                headers = analyzedRequest.getHeaders()
                if headers:
                    self.harvester.harvest_from_headers(headers, url)
                
                # 3. Harvest from POST body parameters
                parameters = analyzedRequest.getParameters()
                if parameters:
                    for param in parameters:
                        param_name = param.getName()
                        param_value = param.getValue()
                        param_type = param.getType()
                        
                        # Determine source type based on parameter type
                        if param_type == 0:  # URL parameter
                            source = 'url_param'
                        elif param_type == 1:  # Body parameter
                            source = 'post_param'
                        elif param_type == 2:  # Cookie
                            source = 'cookie'
                        else:
                            source = 'other_param'
                        
                        if self.harvester._add_finding(param_name, source, url, param_value):
                            # Log new finding
                            findings = [f for f in self.harvester.get_findings() if f.param == param_name.lower()]
                            if findings:
                                self.logParameter(findings[-1])
            
            # Parse response
            response = baseRequestResponse.getResponse()
            if response:
                analyzedResponse = self.helpers.analyzeResponse(response)
                
                # Get response body
                bodyOffset = analyzedResponse.getBodyOffset()
                responseBytes = response[bodyOffset:]
                
                try:
                    responseBody = self.helpers.bytesToString(responseBytes)
                except:
                    responseBody = str(responseBytes)
                
                # 4. Harvest from response headers
                response_headers = analyzedResponse.getHeaders()
                if response_headers:
                    self.harvester.harvest_from_headers(response_headers, url)
                
                # 5. Determine content type and harvest accordingly
                mime_type = analyzedResponse.getStatedMimeType()
                inferred_mime = analyzedResponse.getInferredMimeType()
                
                # HTML content
                if 'HTML' in mime_type or 'HTML' in inferred_mime:
                    before_count = self.harvester.stats['params_found']
                    self.harvester.harvest_from_html(responseBody, url)
                    after_count = self.harvester.stats['params_found']
                    
                    # Log new findings
                    if after_count > before_count:
                        new_findings = self.harvester.get_findings()[-(after_count - before_count):]
                        for finding in new_findings:
                            self.logParameter(finding)
                
                # JavaScript content
                elif 'script' in mime_type.lower() or 'javascript' in mime_type.lower():
                    # Skip common CDN libraries
                    skip_js = False
                    for exclusion in JS_EXCLUSION_LIST:
                        if exclusion in url.lower():
                            skip_js = True
                            break
                    
                    if not skip_js:
                        before_count = self.harvester.stats['params_found']
                        self.harvester.harvest_from_javascript(responseBody, url)
                        after_count = self.harvester.stats['params_found']
                        
                        if after_count > before_count:
                            new_findings = self.harvester.get_findings()[-(after_count - before_count):]
                            for finding in new_findings:
                                self.logParameter(finding)
                
                # JSON content
                elif 'JSON' in mime_type or 'json' in inferred_mime.lower():
                    before_count = self.harvester.stats['params_found']
                    self.harvester.harvest_from_json(responseBody, url)
                    after_count = self.harvester.stats['params_found']
                    
                    if after_count > before_count:
                        new_findings = self.harvester.get_findings()[-(after_count - before_count):]
                        for finding in new_findings:
                            self.logParameter(finding)
                
                # Also check for embedded JavaScript in HTML
                if 'HTML' in mime_type or 'HTML' in inferred_mime:
                    # Extract <script> tag content
                    script_pattern = r'<script[^>]*>(.*?)</script>'
                    scripts = re.findall(script_pattern, responseBody, re.DOTALL | re.IGNORECASE)
                    
                    for script_content in scripts:
                        if len(script_content) > 100:  # Only process substantial scripts
                            before_count = self.harvester.stats['params_found']
                            self.harvester.harvest_from_javascript(script_content, url)
                            after_count = self.harvester.stats['params_found']
                            
                            if after_count > before_count:
                                new_findings = self.harvester.get_findings()[-(after_count - before_count):]
                                for finding in new_findings:
                                    self.logParameter(finding)
            
            # Update statistics in UI
            self.updateStats()
            
        except Exception as e:
            self.stderr.println("[-] Error in doPassiveScan: " + str(e))
            import traceback
            traceback.print_exc(file=self.stderr)
        
        # Return None (no issues to report)
        return None
    
    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        """Consolidate duplicate issues - not used in this extension"""
        return -1
    
    def doActiveScan(self, baseRequestResponse, insertionPoint):
        """Active scanning not implemented"""
        return None


    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        """
        This function makes the tool work on Burp Community Edition via Proxy
        """
        if not messageIsRequest:
            if toolFlag == self.callbacks.TOOL_PROXY:
                self.doPassiveScan(messageInfo)

# ============================================================================
# USAGE INSTRUCTIONS
# ============================================================================
"""
INSTALLATION INSTRUCTIONS:
=========================

1. Open Burp Suite Professional or Community Edition
2. Go to Extender tab > Extensions
3. Click "Add"
4. Select "Python" as Extension type
5. Select this .py file
6. Click "Next"

REQUIREMENTS:
============
- Burp Suite (Professional or Community)
- Jython standalone JAR configured in Extender > Options

USAGE:
======
1. Set your target in "Target" > "Scope"
2. Browse the target application normally
3. Go to "Passive Harvester v2" tab
4. Watch as parameters are discovered automatically
5. Use "Show High Value Only" to see critical parameters
6. Export results as TXT or JSON for further analysis

FEATURES:
=========
✓ Automatic parameter discovery from:
  - URL query strings
  - POST body parameters
  - HTML form fields (input, select, textarea)
  - JSON API responses
  - JavaScript variables and objects
  - HTTP headers (custom headers)
  - Hidden inputs
  - Data attributes

✓ Intelligent scoring system:
  - High value (70+): Auth tokens, admin params, command exec
  - Medium value (40-69): IDOR, XSS, file operations
  - Low value (<40): General parameters

✓ Parameter mutation generation for fuzzing
✓ Duplicate detection
✓ Boring word filtering
✓ Export to TXT/JSON
✓ Real-time statistics

TIPS FOR MAXIMUM EFFECTIVENESS:
===============================
1. Set proper scope - include all subdomains
2. Browse all application features (authenticated and unauthenticated)
3. Trigger AJAX requests and API calls
4. Check "Show High Value Only" regularly for critical findings
5. Export results before starting active scanning
6. Use mutations list for parameter fuzzing in Intruder

SECURITY NOTE:
==============
This tool is for authorized security testing only.
Always obtain proper authorization before testing.

ADVANCED USAGE:
===============
The JSON export includes:
- Parameter names and scores
- Source locations (URL, type)
- Sample values
- Mutation suggestions
- Timestamps

Use this data with other tools like:
- Burp Intruder (for fuzzing)
- Arjun (for parameter discovery validation)
- ParamSpider (for additional recon)
- Custom scripts for mass testing

TROUBLESHOOTING:
================
If no parameters appear:
1. Verify target is in scope
2. Check Burp is intercepting traffic
3. Look at Extender > Errors tab
4. Ensure Jython is properly configured

For support or issues:
- Check the console output in Extender
- Review error logs
- Verify traffic is being proxied through Burp

===========================
Created by: Hwedy00
Version: 2.0 Professional
===========================
"""
