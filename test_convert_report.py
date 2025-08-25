import pytest
import pandas as pd
import tempfile
import os
import json
from convert_report import (
    build_dataframe, 
    generate_html, 
    validate_json_file, 
    validate_output_path,
    remediation_tip,
    is_critical,
    load_config,
    truncate_secret
)

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

def test_build_dataframe_empty():
    df = build_dataframe([])
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 0
    expected_columns = ['Rule', 'Description', 'File', 'Line', 'Secret', 'Remediation', 'Critical']
    assert list(df.columns) == expected_columns

def test_build_dataframe_missing_fields():
    findings = [{"RuleID": "Test", "File": "test.py"}]  # Missing Description and Secret
    df = build_dataframe(findings)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 1
    assert df.iloc[0]['Description'] == 'N/A'
    assert df.iloc[0]['Secret'] == 'N/A'

def test_generate_html():
    df = build_dataframe(sample_findings())
    html = generate_html(df, "Test Report")
    assert isinstance(html, str)
    assert "Test Report" in html
    assert "AWS secret key found" in html
    assert "Hardcoded password" in html

def test_validate_json_file_valid():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump(sample_findings(), f)
        temp_path = f.name
    
    try:
        assert validate_json_file(temp_path) == True
    finally:
        os.unlink(temp_path)

def test_validate_json_file_invalid_json():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("invalid json {")
        temp_path = f.name
    
    try:
        assert validate_json_file(temp_path) == False
    finally:
        os.unlink(temp_path)

def test_validate_json_file_not_list():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        json.dump({"not": "a list"}, f)
        temp_path = f.name
    
    try:
        assert validate_json_file(temp_path) == False
    finally:
        os.unlink(temp_path)

def test_validate_json_file_nonexistent():
    assert validate_json_file("nonexistent_file.json") == False

def test_validate_output_path_valid():
    with tempfile.TemporaryDirectory() as temp_dir:
        output_path = os.path.join(temp_dir, "test.pdf")
        assert validate_output_path(output_path) == True

def test_validate_output_path_create_directory():
    with tempfile.TemporaryDirectory() as temp_dir:
        new_dir = os.path.join(temp_dir, "new_subdir")
        output_path = os.path.join(new_dir, "test.pdf")
        assert validate_output_path(output_path) == True
        assert os.path.exists(new_dir)

def test_remediation_tip():
    assert "Rotate cloud key" in remediation_tip("AWSKey")
    assert "Rotate cloud key" in remediation_tip("GCPToken")
    assert "Reset secret" in remediation_tip("password")
    assert "Remove secret" in remediation_tip("unknown_rule")

def test_is_critical():
    assert is_critical("AWSKey") == True
    assert is_critical("password") == True
    assert is_critical("generic") == False

def test_truncate_secret():
    short_secret = "short"
    assert truncate_secret(short_secret) == short_secret
    
    long_secret = "a" * 50
    truncated = truncate_secret(long_secret)
    assert len(truncated) < len(long_secret)
    assert "..." in truncated

def test_load_config_nonexistent():
    config = load_config("nonexistent.yaml")
    assert config == {}

def test_load_config_valid():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("input: test.json\noutput: test.pdf")
        temp_path = f.name
    
    try:
        config = load_config(temp_path)
        assert config['input'] == 'test.json'
        assert config['output'] == 'test.pdf'
    finally:
        os.unlink(temp_path)

def test_build_dataframe_with_sampling():
    # Create a larger dataset
    large_findings = []
    for i in range(50):
        large_findings.append({
            "RuleID": f"Rule{i % 3}",
            "Description": f"Test finding {i}",
            "File": f"file{i}.py",
            "StartLine": i,
            "Secret": f"secret{i}"
        })
    
    # Test sampling
    df = build_dataframe(large_findings, sample_size=10)
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 10  # Should be limited to sample size

def test_build_dataframe_no_sampling():
    findings = sample_findings()
    df = build_dataframe(findings, sample_size=None)
    assert len(df) == 2  # Should include all findings

def test_load_config_invalid_yaml():
    with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
        f.write("invalid: yaml: content: [")
        temp_path = f.name
    
    try:
        config = load_config(temp_path)
        assert config == {}
    finally:
        os.unlink(temp_path)