# Gitleaks Report Converter

This tool converts Gitleaks JSON reports into a styled PDF (and optionally HTML) report for easy sharing and review.

## Features
- **Grouped, styled PDF report** from Gitleaks JSON with Rule → File → Findings hierarchy
- **Smart secret display**: Long secrets are truncated for better readability (hover to see full secret)
- **Sorted findings**: Critical findings appear first, then sorted by line number
- **Table of contents** and summary with remediation tips
- **CLI options** for input/output, title, and more
- **Timestamped output files** to avoid overwriting existing reports
- **Clean terminal output** with only essential information
- **Config file support** for default settings
- **Progress bar** for large reports
- **Contact information** included in report footer

## Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **(Optional) Run tests:**
   ```bash
   pytest test_convert_report.py
   ```

## Configuration (Optional)

You can create a `config.yaml` file to set default values for input, output, title, and sample size:

```yaml
input: gitleaks-report.json
output: gitleaks-report.pdf
title: Gitleaks Security Scan Report
sample_size: 10
```

CLI arguments will override config.yaml values.

## Usage

```bash
python convert_report.py --input gitleaks-report.json --output gitleaks-report.pdf --title "My Security Report" --html
```

**Arguments:**
- `--input`: Path to Gitleaks JSON file (default: from config.yaml or gitleaks-report.json)
- `--output`: Output PDF file (default: from config.yaml or gitleaks-report.pdf)
- `--title`: Report title (default: from config.yaml or "Gitleaks Security Scan Report")
- `--html`: Also output HTML file
- `--sample-size`: Sample size for time estimation (default: from config.yaml or 10)
- `--log-level`: Logging level (WARNING, ERROR, CRITICAL only)

## Output Files

Reports are automatically timestamped to avoid overwriting:
- **PDF**: `gitleaks-report_20241201_143022.pdf`
- **HTML**: `gitleaks-report_20241201_143022.html`

## Report Structure

- **Rule sections** with descriptions
- **File subsections** with finding counts
- **Findings tables** with Line, Secret (truncated), and Remediation
- **Critical findings** highlighted with red border
- **Contact information**: devsecops@elm.sa

## Example

```bash
python convert_report.py --input my-leaks.json --output my-report.pdf --title "Security Scan" --html
```

## Extending
- Add new remediation tips in `remediation_tip()`
- Customize HTML/CSS in `generate_html()`
- Add more CLI options as needed

## Development
- Progress bar (tqdm) for large reports
- Unit tests in `test_convert_report.py`
- CI setup via GitHub Actions in `.github/workflows/python-app.yml`
- Clean terminal output with summary table

## License
MIT