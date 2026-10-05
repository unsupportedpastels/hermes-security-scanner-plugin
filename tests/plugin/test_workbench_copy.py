"""Plain-language labels and distinct workbench sections."""
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[2] / 'desktop' / 'plugin.js'


def test_plain_evidence_labels():
    text = SOURCE.read_text()
    pairs = {
        'candidate': 'Needs review',
        'source_supported': 'Supported by code',
        'runtime_confirmed': 'Confirmed by test',
        'rejected': 'Not an issue',
        'inconclusive': "Couldn't confirm",
    }
    for state, label in pairs.items():
        assert state in text
        assert label in text
    assert 'NOT RUN' in text


def test_no_marketing_or_ambiguous_validation_copy():
    text = SOURCE.read_text().lower()
    for banned in ['comprehensive', 'robust', 'seamless', 'delve', 'critical insight', 'security posture', 'validation: recorded']:
        assert banned not in text


def test_distinct_sections_and_evidence_limitations():
    text = SOURCE.read_text()
    for section in ['Summary', 'Root cause', 'Attack path', 'Source excerpts', 'Counterevidence', 'Proof gaps', 'Validation', 'Severity assessment', 'Recommended fix', 'Regression tests', 'Patch preview only', 'Coverage and limitations']:
        assert f"title: '{section}'" in text
    assert 'Evidence warning: High confidence was recorded without a source excerpt.' in text
    assert 'Defeating assumptions and controls' in text
    assert 'Zero findings does not establish that a target is safe.' in text
    assert 'No files are changed here.' in text
    assert 'No scan was started.' in text
