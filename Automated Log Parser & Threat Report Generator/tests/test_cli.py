"""Integration tests for the scan.py CLI entrypoint."""
import sys
from pathlib import Path
import pytest
from click.testing import CliRunner

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scan import main


def test_cli_help():
    runner = CliRunner()
    result = runner.invoke(main, ["--help"])
    assert result.exit_code == 0
    assert "Ingest web server access logs" in result.output


def test_cli_scan_attack_demo_log(tmp_path: Path):
    runner = CliRunner()
    demo_log = Path(__file__).resolve().parent.parent / "sample_logs" / "attack_demo.log"
    out_html = tmp_path / "test_report.html"

    result = runner.invoke(main, [str(demo_log), "--out", str(out_html), "--no-rdns"])
    assert result.exit_code == 0
    assert "Pipeline Completed Successfully" in result.output
    assert out_html.exists()
    assert out_html.stat().st_size > 1000

    html_content = out_html.read_text(encoding="utf-8")
    assert "Automated Log Threat Analysis Report" in html_content
    assert "185.220.101.5" in html_content
    assert "SQL Injection" in html_content


def test_cli_scan_all_formats(tmp_path: Path):
    runner = CliRunner()
    demo_log = Path(__file__).resolve().parent.parent / "sample_logs" / "attack_demo.log"
    out_base = tmp_path / "export_all"

    result = runner.invoke(main, [str(demo_log), "--out", str(out_base), "--format", "all", "--no-rdns"])
    assert result.exit_code == 0

    assert (tmp_path / "export_all.html").exists()
    assert (tmp_path / "export_all.md").exists()
    assert (tmp_path / "export_all.json").exists()


if __name__ == "__main__":
    sys.exit(pytest.main(["-v", __file__]))
