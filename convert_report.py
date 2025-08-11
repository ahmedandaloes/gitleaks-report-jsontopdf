import json
import pandas as pd
from weasyprint import HTML, CSS
import html
import time
import argparse
import logging
import os
import yaml
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

def remediation_tip(rule):
    rule = rule.lower()
    if "aws" in rule or "gcp" in rule or "azure" in rule:
        return "Rotate cloud key & remove from code"
    if "password" in rule or "token" in rule or "secret" in rule:
        return "Reset secret & remove from code"
    return "Remove secret from code"

def is_critical(rule):
    rule = rule.lower()
    return any(x in rule for x in ["aws", "gcp", "azure", "password", "token", "secret"])

def load_config(config_path: str = 'config.yaml') -> dict:
    """Load configuration from a YAML file if it exists."""
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    return {}

def truncate_secret(secret: str, max_length: int = 35) -> str:
    """Truncate long secrets for better table display."""
    if not isinstance(secret, str):
        return str(secret)
    if len(secret) <= max_length:
        return secret
    return f"{secret[:25]}...{secret[-10:]}"

def build_dataframe(findings: list) -> pd.DataFrame:
    """Builds and returns a DataFrame from findings with all required columns and computed fields. Shows a progress bar for large reports."""
    # Use tqdm for progress bar if findings is large
    if len(findings) > 100:
        findings_iter = list(tqdm(findings, desc='Processing findings'))
    else:
        findings_iter = findings
    df = pd.DataFrame(findings_iter)
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
    df['Remediation'] = df['RuleID'].map(remediation_tip)
    df['Critical'] = df['RuleID'].map(is_critical)
    # Truncate secrets for better display
    df['Secret'] = df['Secret'].apply(truncate_secret)
    # Sort by Critical (True first), then by Rule (alphabetically), then by File, then by Line (ascending, numeric if possible)
    def line_key(val):
        try:
            return int(val)
        except Exception:
            return float('inf')
    df = df.sort_values(by=['Critical', 'RuleID', 'File', 'Line'], ascending=[False, True, True, True], key=lambda col: col.map(line_key) if col.name == 'Line' else col)
    report_columns = [col for col, _ in useful_columns] + ['Critical']
    df_report = df[report_columns]
    df_report.columns = [name for _, name in useful_columns] + ['Critical']
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

def write_pdf(html_content: str, output_file: str):
    """Writes the HTML content to a PDF file using WeasyPrint."""
    HTML(string=html_content).write_pdf(
        output_file,
        stylesheets=[CSS(string='@page { size: A4 landscape; margin: 1cm; }')]
    )

def print_summary_table(rule_counts: dict):
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

def main():
    config = load_config()
    parser = argparse.ArgumentParser(description="Convert Gitleaks JSON to PDF/HTML report.")
    parser.add_argument('--input', default=config.get('input', 'gitleaks-report.json'), help='Input JSON file')
    parser.add_argument('--output', default=config.get('output', 'gitleaks-report.pdf'), help='Output PDF file')
    parser.add_argument('--title', default=config.get('title', 'Gitleaks Security Scan Report'), help='Report title')
    parser.add_argument('--html', action='store_true', help='Also output HTML file')
    parser.add_argument('--sample-size', type=int, default=config.get('sample_size', 10), help='Sample size for time estimation')
    parser.add_argument('--log-level', default='WARNING', help='Logging level (WARNING, ERROR, CRITICAL)')
    args = parser.parse_args()

    # Force log level to WARNING or higher, regardless of user input
    forced_log_level = logging.WARNING
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

    # Remove sample estimation logic; only generate the full report
    try:
        with open(JSON_INPUT_FILE, 'r') as f:
            findings = json.load(f)
        df_report = build_dataframe(findings)
        html_content = generate_html(df_report, REPORT_TITLE)
        rule_counts = df_report['Rule'].value_counts().to_dict()
        if args.html:
            html_file = f"{base_name}_{timestamp}.html"
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
        write_pdf(html_content, PDF_OUTPUT_FILE)
        print_summary_table(rule_counts)
        print("\nReport generated successfully!\n")
    except Exception as e:
        logging.error(f"Error generating report: {e}")
    logging.warning(f"Finished at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == '__main__':
    main()