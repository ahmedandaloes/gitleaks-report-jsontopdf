import pytest
import pandas as pd
from convert_report import build_dataframe, generate_html

def sample_findings():
    return [
        {
            "RuleID": "AWSKey",
            "Description": "AWS secret key found",
            "File": "main.py",
            "StartLine": 10,
            "Secret": "AKIA...",
        },
        {
            "RuleID": "Password",
            "Description": "Hardcoded password",
            "File": "config.py",
            "StartLine": 42,
            "Secret": "hunter2",
        }
    ]

def test_build_dataframe():
    df = build_dataframe(sample_findings())
    assert isinstance(df, pd.DataFrame)
    assert 'Rule' in df.columns
    assert 'Description' in df.columns
    assert 'File' in df.columns
    assert 'Line' in df.columns
    assert 'Secret' in df.columns
    assert 'Remediation' in df.columns
    assert 'Critical' in df.columns
    assert len(df) == 2

def test_generate_html():
    df = build_dataframe(sample_findings())
    html = generate_html(df, "Test Report")
    assert isinstance(html, str)
    assert "Test Report" in html
    assert "AWS secret key found" in html
    assert "Hardcoded password" in html