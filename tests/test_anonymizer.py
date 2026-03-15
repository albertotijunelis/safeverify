"""Tests for the anonymizer module."""

import json
from unittest.mock import patch, MagicMock

import pytest

from hashguard.anonymizer import (
    _hash_value,
    _redact_text,
    anonymize_row,
    anonymize_rows,
    anonymize_dataset,
    _anonymize_csv,
    _anonymize_jsonl,
    _anonymize_parquet,
    _DROP_COLUMNS,
)


# ── _hash_value ──────────────────────────────────────────────────────────────


class TestHashValue:
    def test_deterministic(self):
        assert _hash_value("hello") == _hash_value("hello")

    def test_default_length_16(self):
        assert len(_hash_value("test")) == 16

    def test_custom_length(self):
        assert len(_hash_value("test", length=8)) == 8

    def test_different_inputs_differ(self):
        assert _hash_value("aaa") != _hash_value("bbb")

    def test_hex_output(self):
        h = _hash_value("x")
        assert all(c in "0123456789abcdef" for c in h)


# ── _redact_text ─────────────────────────────────────────────────────────────


class TestRedactText:
    def test_redact_windows_path(self):
        text = r"Found at C:\Users\admin\malware.exe"
        result = _redact_text(text)
        assert "<REDACTED_PATH>" in result
        assert "admin" not in result

    def test_redact_unix_path(self):
        text = "Saved to /home/analyst/samples/test.bin"
        result = _redact_text(text)
        assert "<REDACTED_PATH>" in result

    def test_redact_email(self):
        text = "Contact analyst@company.com for details"
        result = _redact_text(text)
        assert "<REDACTED_EMAIL>" in result
        assert "analyst@company.com" not in result

    def test_redact_hostname(self):
        text = "Source machine DESKTOP-A1B2C3D4E"
        result = _redact_text(text)
        assert "<REDACTED_HOST>" in result

    def test_no_redaction_needed(self):
        text = "This is a clean string with no PII"
        assert _redact_text(text) == text

    def test_multiple_pii(self):
        text = "Source DESKTOP-A1B2C3D4E found user@test.com at /home/admin/mal.bin"
        result = _redact_text(text)
        assert "<REDACTED_PATH>" in result
        assert "<REDACTED_HOST>" in result
        assert "<REDACTED_EMAIL>" in result


# ── anonymize_row ────────────────────────────────────────────────────────────


class TestAnonymizeRow:
    def test_drops_sensitive_columns(self):
        row = {
            "sha256": "abc123",
            "file_path": "/home/user/test.exe",
            "label_source": "analyst1",
            "label_mb_tags": "trojan,rat",
            "label_mb_signature": "AgentTesla",
        }
        result = anonymize_row(row)
        assert "sha256" in result
        for col in _DROP_COLUMNS:
            assert col not in result

    def test_hashes_filename(self):
        row = {"filename": "malware.exe"}
        result = anonymize_row(row)
        assert result["filename"] != "malware.exe"
        assert len(result["filename"]) == 16

    def test_filename_hash_disabled(self):
        row = {"filename": "malware.exe"}
        result = anonymize_row(row, hash_filename=False)
        assert result["filename"] == "malware.exe"

    def test_filename_none_passthrough(self):
        row = {"filename": None}
        result = anonymize_row(row)
        assert result["filename"] is None

    def test_redacts_description(self):
        row = {"description": r"Found at C:\Users\admin\test.exe"}
        result = anonymize_row(row)
        assert "<REDACTED_PATH>" in result["description"]

    def test_redacts_context(self):
        row = {"context": "user@example.com reported this"}
        result = anonymize_row(row)
        assert "<REDACTED_EMAIL>" in result["context"]

    def test_redacts_details(self):
        row = {"details": "Machine DESKTOP-X1Y2Z3W was infected"}
        result = anonymize_row(row)
        assert "<REDACTED_HOST>" in result["details"]

    def test_passthrough_other_fields(self):
        row = {"sha256": "abc", "malicious": True, "score": 85}
        result = anonymize_row(row)
        assert result == row

    def test_empty_row(self):
        assert anonymize_row({}) == {}


# ── anonymize_rows ───────────────────────────────────────────────────────────


class TestAnonymizeRows:
    def test_multiple_rows(self):
        rows = [
            {"sha256": "a", "file_path": "/x"},
            {"sha256": "b", "file_path": "/y"},
        ]
        result = anonymize_rows(rows)
        assert len(result) == 2
        assert all("file_path" not in r for r in result)

    def test_empty_list(self):
        assert anonymize_rows([]) == []


# ── _anonymize_csv ───────────────────────────────────────────────────────────


class TestAnonymizeCsv:
    def test_basic_csv(self):
        csv_data = "sha256,filename,file_path\nabc,test.exe,/home/user/test.exe\n"
        result = _anonymize_csv(csv_data)
        assert "sha256" in result
        assert "filename" in result
        assert "file_path" not in result
        assert "/home/user" not in result

    def test_empty_csv(self):
        result = _anonymize_csv("")
        assert result == ""

    def test_preserves_rows(self):
        csv_data = "sha256,score\na,1\nb,2\nc,3\n"
        result = _anonymize_csv(csv_data)
        lines = result.strip().split("\n")
        assert len(lines) == 4  # header + 3 data rows


# ── _anonymize_jsonl ─────────────────────────────────────────────────────────


class TestAnonymizeJsonl:
    def test_basic_jsonl(self):
        data = '{"sha256":"a","file_path":"/x"}\n{"sha256":"b","file_path":"/y"}\n'
        result = _anonymize_jsonl(data)
        lines = result.strip().split("\n")
        assert len(lines) == 2
        for line in lines:
            obj = json.loads(line)
            assert "sha256" in obj
            assert "file_path" not in obj

    def test_empty_jsonl(self):
        result = _anonymize_jsonl("")
        assert result == ""


# ── _anonymize_parquet ───────────────────────────────────────────────────────


class TestAnonymizeParquet:
    def test_without_pyarrow(self):
        """When pyarrow is not available, returns raw data."""
        with patch.dict("sys.modules", {"pyarrow": None, "pyarrow.parquet": None}):
            data = b"fake parquet data"
            # Need to reimport to trigger the ImportError
            with patch("hashguard.anonymizer.logger"):
                result = _anonymize_parquet(data)
                # Should return raw data since import fails
                assert isinstance(result, bytes)

    def test_with_pyarrow(self):
        """If pyarrow is installed, test full parquet anonymization."""
        try:
            import pyarrow as pa
            import pyarrow.parquet as pq
            import io
        except ImportError:
            pytest.skip("pyarrow not installed")

        table = pa.table({
            "sha256": ["abc", "def"],
            "filename": ["test.exe", "mal.dll"],
            "file_path": ["/tmp/x", "/tmp/y"],
            "score": [80, 90],
        })
        buf = io.BytesIO()
        pq.write_table(table, buf)
        raw = buf.getvalue()

        result = _anonymize_parquet(raw)
        result_table = pq.read_table(io.BytesIO(result))
        assert "file_path" not in result_table.column_names
        assert "sha256" in result_table.column_names
        assert result_table.num_rows == 2


# ── anonymize_dataset ────────────────────────────────────────────────────────


class TestAnonymizeDataset:
    def test_csv_format(self):
        data = "sha256,file_path\na,/x\n"
        result = anonymize_dataset(data, fmt="csv")
        assert "file_path" not in result

    def test_jsonl_format(self):
        data = '{"sha256":"a","file_path":"/x"}\n'
        result = anonymize_dataset(data, fmt="jsonl")
        obj = json.loads(result)
        assert "file_path" not in obj

    def test_default_is_csv(self):
        data = "sha256,score\na,1\n"
        result = anonymize_dataset(data)
        assert "sha256" in result
