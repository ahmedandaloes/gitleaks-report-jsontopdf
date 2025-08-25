"""
Gitleaks Report Converter

This tool converts Gitleaks JSON reports into styled PDF and HTML reports
with enhanced visualization, sorting, and customization options.

Features:
- Convert JSON findings to PDF/HTML with professional styling
- Automatic validation of input files and paths
- Progress bars for large reports
- Rich terminal output with summary tables
- Flexible configuration via YAML files or CLI arguments
- Comprehensive error handling and logging

Author: Ahmed Andaloes
License: MIT
"""

import json
import pandas as pd
from weasyprint import HTML, CSS
import html
import time
import argparse
import logging
import os
import sys
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from tqdm import tqdm

try:
    from rich.logging import RichHandler
    from rich.console import Console
    from rich.table import Table
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

# --- Configuration ---
JSON_INPUT_FILE = 'gitleaks-report.json'
PDF_OUTPUT_FILE = 'gitleaks-report.pdf'
REPORT_TITLE = 'Gitleaks Security Scan Report'
# -------------------

def validate_json_file(file_path: str) -> bool:
    """Validate that the JSON file exists and contains valid JSON data."""
    if not os.path.exists(file_path):
        logging.error(f"Input file does not exist: {file_path}")
        return False
    
    # Check file size for performance warnings
    file_size = os.path.getsize(file_path)
    if file_size > 10 * 1024 * 1024:  # 10MB
        logging.warning(f"Large input file detected ({file_size/1024/1024:.1f}MB). Processing may take some time.")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if not isinstance(data, list):
                logging.error(f"JSON file must contain a list of findings, got {type(data).__name__}")
                return False
            if len(data) > 10000:
                logging.warning(f"Large number of findings detected ({len(data)}). Consider using --sample-size for initial review.")
            logging.info(f"Successfully validated JSON file with {len(data)} findings")
            return True
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in file {file_path}: {e}")
        return False
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {e}")
        return False

def validate_output_path(file_path: str) -> bool:
    """Validate that the output directory exists and is writable."""
    output_dir = os.path.dirname(os.path.abspath(file_path))
    
    if not os.path.exists(output_dir):
        try:
            os.makedirs(output_dir, exist_ok=True)
            logging.info(f"Created output directory: {output_dir}")
        except Exception as e:
            logging.error(f"Cannot create output directory {output_dir}: {e}")
            return False
    
    if not os.access(output_dir, os.W_OK):
        logging.error(f"Output directory is not writable: {output_dir}")
        return False
    
    return True

def remediation_tip(rule: str) -> str:
    """Return appropriate remediation tip based on the rule type."""
    rule = rule.lower()
    if "aws" in rule or "gcp" in rule or "azure" in rule:
        return "Rotate cloud key & remove from code"
    if "password" in rule or "token" in rule or "secret" in rule:
        return "Reset secret & remove from code"
    return "Remove secret from code"

def is_critical(rule: str) -> bool:
    """Determine if a rule represents a critical security finding."""
    rule = rule.lower()
    return any(x in rule for x in ["aws", "gcp", "azure", "password", "token", "secret"])

def load_config(config_path: str = 'config.yaml') -> Dict[str, Any]:
    """Load configuration from a YAML file if it exists."""
    if os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                if not isinstance(config, dict):
                    logging.warning(f"Configuration file {config_path} does not contain a dictionary, using defaults")
                    return {}
                logging.info(f"Loaded configuration from {config_path}")
                return config
        except yaml.YAMLError as e:
            logging.error(f"Invalid YAML in config file {config_path}: {e}")
            return {}
        except Exception as e:
            logging.error(f"Error reading config file {config_path}: {e}")
            return {}
    return {}

def truncate_secret(secret: str, max_length: int = 35) -> str:
    """Truncate long secrets for better table display."""
    if not isinstance(secret, str):
        return str(secret)
    if len(secret) <= max_length:
        return secret
    return f"{secret[:25]}...{secret[-10:]}"

def build_dataframe(findings: List[Dict[str, Any]], sample_size: Optional[int] = None) -> pd.DataFrame:
    """Builds and returns a DataFrame from findings with all required columns and computed fields. Shows a progress bar for large reports."""
    if not findings:
        logging.warning("No findings provided, creating empty DataFrame")
        return pd.DataFrame(columns=['Rule', 'Description', 'File', 'Line', 'Secret', 'Remediation', 'Critical'])
    
    # Apply sampling if requested for very large datasets
    original_count = len(findings)
    if sample_size and sample_size > 0 and len(findings) > sample_size:
        logging.warning(f"Sampling {sample_size} findings from {original_count} total findings")
        import random
        findings = random.sample(findings, sample_size)
    
    # Validate findings structure
    required_fields = ['RuleID', 'Description', 'File', 'Secret']
    invalid_findings = 0
    for i, finding in enumerate(findings):
        if not isinstance(finding, dict):
            logging.error(f"Finding {i} is not a dictionary: {type(finding)}")
            invalid_findings += 1
            continue
        
        missing_fields = [field for field in required_fields if field not in finding]
        if missing_fields:
            logging.warning(f"Finding {i} missing required fields: {missing_fields}")
    
    if invalid_findings > 0:
        logging.warning(f"Found {invalid_findings} invalid findings that will be skipped")
    
    # Use tqdm for progress bar if findings is large
    if len(findings) > 100:
        findings_iter = list(tqdm(findings, desc='Processing findings'))
    else:
        findings_iter = findings
        
    df = pd.DataFrame(findings_iter)
    
    # Handle missing columns with defaults
    if 'StartLine' in df.columns:
        df['Line'] = df['StartLine']
    else:
        df['Line'] = 'N/A'
    
    useful_columns = [
        ('RuleID', 'Rule'),
        ('Description', 'Description'),
        ('File', 'File'),
        ('Line', 'Line'),
        ('Secret', 'Secret'),
        ('Remediation', 'Remediation')
    ]
    
    for col, _ in useful_columns:
        if col not in df.columns:
            df[col] = 'N/A'
            logging.warning(f"Missing column '{col}' in findings, using default value 'N/A'")
    
    df['Remediation'] = df['RuleID'].map(remediation_tip)
    df['Critical'] = df['RuleID'].map(is_critical)
    
    # Truncate secrets for better display
    df['Secret'] = df['Secret'].apply(truncate_secret)
    
    # Sort by Critical (True first), then by Rule (alphabetically), then by File, then by Line (ascending, numeric if possible)
    def line_key(val: Any) -> Union[int, float]:
        try:
            return int(val)
        except (ValueError, TypeError):
            return float('inf')
    
    df = df.sort_values(
        by=['Critical', 'RuleID', 'File', 'Line'], 
        ascending=[False, True, True, True], 
        key=lambda col: col.map(line_key) if col.name == 'Line' else col
    )
    
    report_columns = [col for col, _ in useful_columns] + ['Critical']
    df_report = df[report_columns]
    df_report.columns = [name for _, name in useful_columns] + ['Critical']
    
    if sample_size and original_count > len(df_report):
        logging.info(f"Built DataFrame with {len(df_report)} findings (sampled from {original_count})")
    else:
        logging.info(f"Built DataFrame with {len(df_report)} findings")
    
    return df_report

def generate_html(df_report: pd.DataFrame, report_title: str) -> str:
    """Generates the HTML report from the DataFrame and returns it as a string."""
    escape = html.escape
    total_findings = len(df_report)
    rule_counts = df_report['Rule'].value_counts().to_dict()
    # Sort rules alphabetically for consistent ordering
    sorted_rules = sorted(rule_counts.items())
    rule_summary = "".join(
        f"<li><a href='#{escape(rule)}'><b>{escape(rule)}</b></a>: {count}</li>" for rule, count in sorted_rules
    )
    toc = "<ul>" + "".join(
        f"<li><a href='#{escape(rule)}'>{escape(rule)} ({count})</a></li>" for rule, count in sorted_rules
    ) + "</ul>"
    grouped = df_report.groupby(['Rule', 'File'], sort=False)
    grouped_tables_list = []
    current_rule = None
    for idx, ((rule, file), group) in enumerate(grouped):
        page_break = "<div style='page-break-before: always;'></div>" if idx > 0 and rule != current_rule else ""
        def row_style(is_critical):
            return 'style="border-left: 5px solid #d32f2f;"' if is_critical else ""
        description = escape(str(group.iloc[0]['Description']))
        # Remove Rule, File, and Description from columns
        columns = [col for col in group.columns if col not in ("Critical", "Description", "Rule", "File")]
        
        # Show rule heading only when rule changes
        rule_heading = ""
        if rule != current_rule:
            rule_heading = f'<h2 id="{escape(rule)}" style="color:#1a237e; margin-top:2em;">{escape(rule)} <span style="font-size:0.7em; color:#888;">({df_report[df_report["Rule"] == rule].shape[0]})</span></h2>'
            rule_heading += f'<div class="rule-description-info">{description}</div>'
            current_rule = rule
        
        # File sub-heading
        file_heading = f'<h3 style="color:#424242; margin-top:1.5em; margin-bottom:0.5em;">📁 {escape(file)} <span style="font-size:0.7em; color:#888;">({len(group)})</span></h3>'
        
        rows = [
            f'<tr {row_style(row.Critical)}>' +
            ''.join(f'<td class="{escape(col)}">{escape(str(getattr(row, col)))}</td>' for col in columns) +
            '</tr>'
            for row in group.itertuples(index=False, name="Row")
        ]
        grouped_tables_list.append(
            f"""{page_break}
            {rule_heading}
            {file_heading}
            <table class="leak-table">
                <thead>
                    <tr>
                        {''.join(f'<th>{escape(col)}</th>' for col in columns)}
                    </tr>
                </thead>
                <tbody>
                    {''.join(rows)}
                </tbody>
            </table>
            """
        )
    grouped_tables = ''.join(grouped_tables_list)
    css_styles = """
        body {
            font-family: 'Segoe UI', Arial, sans-serif;
            background: #f8f9fa;
            margin: 0;
            padding: 0;
        }
        .container {
            max-width: 1200px;
            margin: 30px auto;
            background: #fff;
            border-radius: 12px;
            border: 1px solid #e0e0e0;
            padding: 32px 40px 40px 40px;
        }
        h1 {
            color: #2d3e50;
            font-size: 2.2em;
            margin-bottom: 0.2em;
        }
        .summary {
            background: #f1f3f6;
            border-radius: 8px;
            padding: 16px 24px;
            margin-bottom: 2em;
            font-size: 1.1em;
        }
        .summary ul {
            margin: 0 0 0 1.5em;
        }
        .toc {
            background: #e3e7f0;
            border-radius: 8px;
            padding: 12px 20px;
            margin-bottom: 2em;
            font-size: 1.05em;
        }
        .info-box {
            background: #e8f5e9;
            border-left: 5px solid #388e3c;
            padding: 16px 24px;
            margin-bottom: 2em;
            font-size: 1.08em;
        }
        .rule-description-info {
            background: #fffde7;
            border-left: 5px solid #fbc02d;
            padding: 12px 20px;
            margin-bottom: 1.2em;
            font-size: 1.05em;
            color: #7c6f00;
            border-radius: 6px;
        }
        p {
            color: #555;
            margin-bottom: 2em;
        }
        table.leak-table {
            border-collapse: separate;
            border-spacing: 0;
            width: 100%;
            font-size: 1em;
            background: #fff;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #e0e0e0;
            margin-bottom: 2em;
        }
        table.leak-table th, table.leak-table td {
            padding: 12px 10px;
            text-align: left;
            vertical-align: top;
            border-bottom: 1px solid #eaeaea;
            word-break: break-all;
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
        }
        table.leak-table th {
            background: #f1f3f6;
            color: #2d3e50;
            font-weight: 600;
            font-size: 1.05em;
        }
        table.leak-table tr:last-child td {
            border-bottom: none;
        }
        table.leak-table tr:nth-child(even) {
            background: #f9fbfd;
        }
        table.leak-table td.Secret {
            color: #b71c1c;
            font-family: 'Fira Mono', 'Consolas', monospace;
            font-size: 0.98em;
            background: #fff5f5;
            border: 1px solid #ffcdd2;
            border-radius: 4px;
            padding: 8px 10px;
            max-width: 250px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }
        .footer {
            margin-top: 40px;
            color: #888;
            font-size: 0.95em;
            text-align: center;
        }
    """
    html_content = f"""
    <html>
        <head>
            <title>{report_title}</title>
            <style>{css_styles}</style>
        </head>
        <body>
            <div class="container">
                <div class="info-box">
                    <b>Why Secret Management?</b><br>
                    Secrets (API keys, passwords, tokens) in code can lead to data breaches and service compromise.<br>
                    <b>What to do?</b> Remove secrets from code, rotate exposed keys, and use secret management tools.
                </div>
                <h1>{report_title}</h1>
                <div class="summary">
                    <b>Total Findings:</b> {total_findings}
                    <ul>
                        {rule_summary}
                    </ul>
                </div>
                <div class="toc">
                    <b>Table of Contents:</b>
                    {toc}
                </div>
                <p>Generated on: {pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                {grouped_tables}
                <div class="footer">
                    <hr>
                    <p>For questions or incident response, contact your security team at <b>devsecops@elm.sa</b></p>
                </div>
            </div>
        </body>
    </html>
    """
    return html_content

def write_pdf(html_content: str, output_file: str) -> bool:
    """Writes the HTML content to a PDF file using WeasyPrint."""
    try:
        HTML(string=html_content).write_pdf(
            output_file,
            stylesheets=[CSS(string='@page { size: A4 landscape; margin: 1cm; }')]
        )
        logging.info(f"Successfully wrote PDF to {output_file}")
        return True
    except Exception as e:
        logging.error(f"Failed to write PDF to {output_file}: {e}")
        return False

def print_summary_table(rule_counts: Dict[str, int]) -> None:
    """Print a summary table of findings by rule type."""
    if RICH_AVAILABLE:
        console = Console()
        table = Table(title="Findings Summary", show_lines=True)
        table.add_column("Rule", style="bold cyan")
        table.add_column("Count", style="bold yellow")
        for rule, count in rule_counts.items():
            table.add_row(str(rule), str(count))
        console.print(table)
    else:
        print("\nFindings Summary:")
        print("Rule".ljust(30), "Count")
        print("-"*40)
        for rule, count in rule_counts.items():
            print(str(rule).ljust(30), str(count))

def main() -> None:
    """Main function to convert Gitleaks JSON report to PDF/HTML."""
    config = load_config()
    parser = argparse.ArgumentParser(
        description="Convert Gitleaks JSON to PDF/HTML report.",
        epilog="Example: python convert_report.py --input gitleaks-report.json --output report.pdf --html",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--input', 
                       default=config.get('input', 'gitleaks-report.json'), 
                       help='Input JSON file path')
    parser.add_argument('--output', 
                       default=config.get('output', 'gitleaks-report.pdf'), 
                       help='Output PDF file path')
    parser.add_argument('--title', 
                       default=config.get('title', 'Gitleaks Security Scan Report'), 
                       help='Report title')
    parser.add_argument('--html', 
                       action='store_true', 
                       help='Also generate HTML file')
    parser.add_argument('--sample-size', 
                       type=int, 
                       default=config.get('sample_size', 0), 
                       help='Limit report to N findings for large datasets (0=all)')
    parser.add_argument('--log-level', 
                       choices=['WARNING', 'ERROR', 'CRITICAL', 'INFO'],
                       default='WARNING', 
                       help='Logging level')
    parser.add_argument('--version', 
                       action='version', 
                       version='%(prog)s 2.0')
    args = parser.parse_args()

    # Validate arguments
    if not args.input:
        logging.error("Input file path is required")
        sys.exit(1)
        
    if not args.output:
        logging.error("Output file path is required")
        sys.exit(1)
    
    if args.sample_size < 0:
        logging.error("Sample size must be non-negative")
        sys.exit(1)

    # Force log level to WARNING or higher, unless INFO is explicitly requested
    log_level = args.log_level.upper()
    if log_level == 'INFO':
        forced_log_level = logging.INFO
    else:
        forced_log_level = getattr(logging, log_level)
    
    if RICH_AVAILABLE:
        logging.basicConfig(
            level=forced_log_level,
            format='%(message)s',
            datefmt="[%X]",
            handlers=[RichHandler(rich_tracebacks=True)]
        )
    else:
        logging.basicConfig(
            level=forced_log_level,
            format='%(levelname)s: %(message)s'
        )

    # Validate input file
    if not validate_json_file(args.input):
        sys.exit(1)
    
    # Validate output path
    if not validate_output_path(args.output):
        sys.exit(1)

    global JSON_INPUT_FILE, PDF_OUTPUT_FILE, REPORT_TITLE, SAMPLE_SIZE
    JSON_INPUT_FILE = args.input
    REPORT_TITLE = args.title
    SAMPLE_SIZE = args.sample_size

    # Add timestamp to output filename to avoid replacing existing files
    import datetime
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    base_name = args.output.replace('.pdf', '').replace('.html', '')
    PDF_OUTPUT_FILE = f"{base_name}_{timestamp}.pdf"

    logging.warning(f"Started at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        # Load and process findings
        with open(JSON_INPUT_FILE, 'r', encoding='utf-8') as f:
            findings = json.load(f)
        
        if not findings:
            logging.warning("No findings in input file, generating empty report")
        
        df_report = build_dataframe(findings, args.sample_size if args.sample_size > 0 else None)
        html_content = generate_html(df_report, REPORT_TITLE)
        rule_counts = df_report['Rule'].value_counts().to_dict() if len(df_report) > 0 else {}
        
        # Generate HTML file if requested
        if args.html:
            html_file = f"{base_name}_{timestamp}.html"
            try:
                with open(html_file, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                logging.info(f"Successfully wrote HTML to {html_file}")
            except Exception as e:
                logging.error(f"Failed to write HTML file: {e}")
        
        # Generate PDF
        if not write_pdf(html_content, PDF_OUTPUT_FILE):
            sys.exit(1)
        
        # Print summary
        if rule_counts:
            print_summary_table(rule_counts)
        
        print(f"\nReport generated successfully!")
        print(f"PDF: {PDF_OUTPUT_FILE}")
        if args.html:
            print(f"HTML: {html_file}")
        print()
        
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in input file: {e}")
        sys.exit(1)
    except FileNotFoundError:
        logging.error(f"Input file not found: {JSON_INPUT_FILE}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Unexpected error generating report: {e}")
        sys.exit(1)
    
    logging.warning(f"Finished at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == '__main__':
    main()