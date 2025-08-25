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
- **Input validation** and comprehensive error handling
- **Performance optimizations** for large datasets with sampling support
- **Enhanced logging** with multiple levels and rich output
- **Version information** and improved help system

## Setup

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **(Optional) Run tests:**
   ```bash
   pytest test_convert_report.py -v
   ```

## Configuration (Optional)

You can create a `config.yaml` file to set default values for input, output, title, and sample size:

```yaml
input: gitleaks-report.json
output: gitleaks-report.pdf
title: Gitleaks Security Scan Report
sample_size: 0  # 0 = process all findings
```

See `config.yaml.example` for more configuration options and examples.

CLI arguments will override config.yaml values.

## Usage

```bash
python convert_report.py --input gitleaks-report.json --output gitleaks-report.pdf --title "My Security Report" --html
```

**Arguments:**
- `--input`: Path to Gitleaks JSON file (default: from config.yaml or gitleaks-report.json)
- `--output`: Output PDF file path (default: from config.yaml or gitleaks-report.pdf)
- `--title`: Report title (default: from config.yaml or "Gitleaks Security Scan Report")
- `--html`: Also generate HTML file
- `--sample-size`: Limit report to N findings for large datasets (0=all, default: 0)
- `--log-level`: Logging level (WARNING, ERROR, CRITICAL, INFO)
- `--version`: Show version information

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
- Extend validation in `validate_json_file()` for custom requirements

## Development
- **Enhanced error handling** and input validation
- **Comprehensive type hints** for better IDE support
- **Progress bar** (tqdm) for large reports
- **Extensive unit tests** in `test_convert_report.py`
- **CI setup** via GitHub Actions in `.github/workflows/python-app.yml`
- **Clean terminal output** with summary table using Rich library
- **Performance optimizations** for large datasets
- **Modular code structure** for easy extension

## License
MIT