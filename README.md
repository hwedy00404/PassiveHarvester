# PassiveHarvester
![Python](https://img.shields.io/badge/Python-2.7%2B-blue)
![Burp Suite](https://img.shields.io/badge/Burp%20Suite-Pro%20%26%20Community-orange)
![License](https://img.shields.io/badge/License-MIT-green)

Advanced Passive Harvester is a professional-grade Burp Suite extension designed for web application security experts. It passively discovers and analyzes parameters from in-scope traffic, providing valuable insights for security testing without sending a single active request. The tool intelligently scores parameters based on their potential security impact, helping testers prioritize their efforts.

## Features

✓ **Automatic Parameter Discovery**: Passively harvests parameters from diverse sources including:
  - URL query strings
  - POST body parameters
  - Custom HTTP headers (e.g., `X-*`, `API-*`)
  - HTML content (forms, inputs, select, textarea, `data-*` attributes)
  - JavaScript files (variables, object keys, function parameters, API endpoints)
  - JSON API responses

✓ **Intelligent Scoring System**: Assigns a score to each discovered parameter to highlight its potential importance for security testing.
  - **High Value (70+)**: Critical identifiers like auth tokens, session keys, admin parameters, and command execution keywords.
  - **Medium Value (40-69)**: Parameters related to IDOR, XSS, file operations, and redirects.
  - **Low Value (<40)**: General, less critical parameters.

✓ **Parameter Mutation Generation**: Suggests common variations for discovered parameters (e.g., case changes, delimiter swapping, array notations) to aid in fuzzing and manual testing.

✓ **Advanced Noise Reduction**: Utilizes a comprehensive list of "boring words" and filters for common JS libraries to minimize noise and focus on relevant findings.

✓ **Interactive Burp Suite Tab**: Provides a dedicated UI tab within Burp Suite to view findings in real-time, see statistics, and manage the results.

✓ **Data Export**: Findings can be exported in both human-readable TXT format and structured JSON format for use with other tools or for reporting.

✓ **Broad Compatibility**: Fully compatible with both Burp Suite Professional and Community editions (using the Proxy listener).

## Requirements

*   Burp Suite (Professional or Community Edition)
*   Jython Standalone JAR file configured in Burp Suite (`Extender` > `Options`).

## Installation

1.  Open Burp Suite.
2.  Navigate to the `Extender` tab, then click the `Extensions` sub-tab.
3.  Click the "Add" button.
4.  Set the "Extension type" to "Python".
5.  Click "Select file..." and choose the `AdvancedPassiveHarvester.py` file.
6.  Click "Next" to complete the installation.
7.  A new tab labeled "Passive Harvester v2" should appear in your Burp Suite UI.

## Usage

1.  **Set Your Scope**: Add your target application to the scope in the `Target` > `Scope` tab. The harvester will only process in-scope items.
2.  **Browse the Application**: Use your browser to navigate and interact with the target application as you normally would. Ensure your browser's traffic is being proxied through Burp Suite.
3.  **View Findings**: Go to the "Passive Harvester v2" tab to see discovered parameters appear in real-time.
4.  **Analyze**: Use the UI options to analyze the findings:
    *   **Refresh Stats**: Update the statistics summary.
    *   **Show High Value Only**: Filter the view to display only parameters with a score of 70 or higher.
    *   **Export**: Save your findings to a TXT or JSON file for further analysis or reporting.
    *   **Clear Log**: Reset the harvester and clear the display.

## UI Overview


https://github.com/user-attachments/assets/291e94a6-3606-4868-bd21-502b1bcd91f5




The extension provides a clean and functional tab in Burp Suite:
*   **Title and Statistics**: At the top, you'll find the extension title and a real-time summary of harvested parameters, categorized by score (High, Medium, Low).
*   **Main Log Area**: The central text area displays discovered parameters, their score, source (e.g., `json_key`, `html_attr`), the URL where they were found, and suggested mutations. High-value parameters are highlighted for easy identification.
*   **Control Buttons**:
    *   `Clear Log`: Clears all findings from the UI and resets the internal state.
    *   `Export as TXT`: Saves the findings in a formatted text report.
    *   `Export as JSON`: Saves the findings, including all metadata and mutations, in a structured JSON file.
    *   `Show High Value Only`: Filters the main log to show only high-score parameters.
    *   `Refresh Stats`: Manually updates the statistics displayed at the top.

## Exporting Data

### TXT Export
The text export provides a clean, human-readable report sorted by score, perfect for quick reviews or manual analysis.

```text
[Score: 90] auth_token
  Source: header
  URL: https://example.com/api/v1/user/profile
  Sample: Bearer
  Mutations: X-auth_token, auth_token_param, authTokenId...

[Score: 75] user_id
  Source: json_key
  URL: https://example.com/api/v1/user/profile
  Sample: 12345
  Mutations: USER_ID, user-id, userId[]...
```

### JSON Export
The JSON export is ideal for machine-readable output and integration with other security tools or custom scripts. It contains detailed information about each finding.

```json
{
  "metadata": {
    "tool": "Advanced Passive Harvester",
    "export_time": "...",
    "statistics": {
      "total_scanned": 150,
      "params_found": 35,
      "high_value": 4,
      "medium_value": 12,
      "low_value": 19
    }
  },
  "findings": [
    {
      "parameter": "auth_token",
      "source_type": "header",
      "url": "https://example.com/api/v1/user/profile",
      "sample_value": null,
      "score": 90,
      "mutations": [
        "AUTH_TOKEN",
        "auth-token",
        "authToken",
        "authToken[]",
        ...
      ],
      "timestamp": 1677610000.123
    }
  ]
}
```

## ⚖️ Legal
Designed for security professionals to analyze authorized traffic only. Use responsibly.
