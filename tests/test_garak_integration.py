import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from modelguard.cli import main
from modelguard.config import load_scan_config
from modelguard.evidence.redaction import redact_text
from modelguard.garak.command_builder import build_garak_command, build_generator_options
from modelguard.garak.normalizer import normalize_garak_report
from modelguard.garak.parser import parse_garak_report
from modelguard.garak.runner import GarakRunArtifacts


FIXTURE_JSONL = "garak-sample-output/garak-evidence/garak-reports/modelguard-deepseek-test.report.jsonl"


def _config(tmp_path: Path):
    args = SimpleNamespace(
        config="configs/local-ollama-garak.yaml",
        target="ollama",
        model="deepseek-r1:14b",
        base_url="http://localhost:11434",
        probes="test.Test",
        detectors=None,
        timeout=120,
        out=str(tmp_path / "reports" / "scan.md"),
        fail_on=None,
    )
    with patch("modelguard.config._local_filename_timestamp", return_value="2026-05-15_20-34-21"):
        return load_scan_config(args)


def test_command_builder_includes_ollama_target_and_report_prefix():
    with TemporaryDirectory() as temp_dir:
        config = _config(Path(temp_dir))
        command = build_garak_command(config, "/tmp/garak-prefix")
        assert command[:3] == ["python3", "-m", "garak"]
        assert "--target_type" in command
        assert "--target_name" in command
        assert "--report_prefix" in command
        assert "test.Test" in command
        options = build_generator_options(config)
        assert options["ollama"]["OllamaGeneratorChat"]["host"] == "localhost:11434"
        assert options["ollama"]["OllamaGeneratorChat"]["timeout"] == 60


def test_parser_extracts_required_metadata_from_pinned_sample():
    parsed = parse_garak_report(FIXTURE_JSONL)
    assert parsed["metadata"]["garak_version"] == "0.15.0"
    assert parsed["metadata"]["run_uuid"] == "272831d6-c49d-46e7-91fc-b383c1f42b76"
    assert parsed["metadata"]["target_type"] == "ollama"
    assert parsed["metadata"]["target_name"] == "deepseek-r1:14b"
    assert parsed["metadata"]["probe_spec"] == "test.Test"
    assert parsed["metadata"]["detector_spec"] == "auto"
    assert parsed["metadata"]["report_filename"] == "modelguard-deepseek-test.report.jsonl"
    assert parsed["probe_names"] == ["test.Test"]
    assert parsed["detector_names"] == ["always.Pass"]
    assert parsed["eval_summaries"][0]["score"] == 1.0
    assert parsed["eval_summaries"][0]["defcon"] == 5
    assert parsed["eval_summaries"][0]["total_evaluated"] == 40
    assert parsed["eval_summaries"][0]["passed"] == 40


def test_normalizer_preserves_garak_semantics_without_custom_scoring():
    with TemporaryDirectory() as temp_dir:
        config = _config(Path(temp_dir))
        parsed = parse_garak_report(FIXTURE_JSONL)
        artefacts = GarakRunArtifacts(
            artifact_dir=str(Path(temp_dir) / "reports" / "garak" / config.scan_id),
            report_prefix=str(Path(temp_dir) / "reports" / "garak" / config.scan_id / "garak-reports" / config.scan_id),
            command=["python3", "-m", "garak"],
            exit_code=0,
            runtime_seconds=12.5,
            timed_out=False,
            stdout_path=str(Path(temp_dir) / "stdout.log"),
            stderr_path=str(Path(temp_dir) / "stderr.log"),
            command_path=str(Path(temp_dir) / "command_used.txt"),
            runtime_metadata_path=str(Path(temp_dir) / "runtime_metadata.json"),
            environment_path=str(Path(temp_dir) / "environment.txt"),
            jsonl_reports=[FIXTURE_JSONL],
            html_reports=["garak-sample-output/garak-evidence/garak-reports/modelguard-deepseek-test.report.html"],
            hitlog_reports=[],
        )
        scan_result = normalize_garak_report(parsed, config, artefacts)
        payload = scan_result.to_dict()
        assert payload["scan"]["scanner"] == "garak"
        assert payload["summary"]["total_probes"] == 1
        assert payload["summary"]["passed"] == 1
        assert payload["summary"]["highest_severity"] == "DEFCON 5"
        assert payload["results"][0]["probe_id"] == "test.Test"
        assert payload["results"][0]["severity"] == "DEFCON 5"
        assert payload["results"][0]["detector_results"][0]["detector_id"] == "always.Pass"
        assert payload["results"][0]["detector_results"][0]["passed_count"] == 40
        assert payload["results"][0]["detector_results"][0]["total_evaluated"] == 40
        assert payload["evidence"]["jsonl_reports"] == [FIXTURE_JSONL]


def test_redaction_masks_sensitive_values():
    redacted = redact_text("sk-1234567890abcdefgh bearer ABCDEFGHIJKLMN user@example.com")
    assert "sk-1234567890abcdefgh" not in redacted
    assert "ABCDEFGHIJKLMN" not in redacted
    assert "user@example.com" not in redacted


def test_scan_smoke_uses_fixture_reports_without_live_ollama(tmp_path: Path):
    fixture_jsonl = Path(FIXTURE_JSONL)
    fixture_html = fixture_jsonl.with_suffix(".html")

    def fake_run_garak(command, artifact_dir, report_prefix, timeout_seconds, extra_env=None):
        report_dir = Path(report_prefix).parent
        report_dir.mkdir(parents=True, exist_ok=True)
        jsonl_dest = report_dir / f"{Path(report_prefix).name}.report.jsonl"
        html_dest = report_dir / f"{Path(report_prefix).name}.report.html"
        jsonl_dest.write_text(fixture_jsonl.read_text(encoding="utf-8"), encoding="utf-8")
        html_dest.write_text(fixture_html.read_text(encoding="utf-8"), encoding="utf-8")
        stdout_path = Path(artifact_dir) / "stdout.log"
        stderr_path = Path(artifact_dir) / "stderr.log"
        command_path = Path(artifact_dir) / "command_used.txt"
        runtime_path = Path(artifact_dir) / "runtime_metadata.json"
        env_path = Path(artifact_dir) / "environment.txt"
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        stdout_path.write_text("garak ok\n", encoding="utf-8")
        stderr_path.write_text("", encoding="utf-8")
        command_path.write_text("python3 -m garak\n", encoding="utf-8")
        runtime_path.write_text(json.dumps({"exit_code": 0}, indent=2), encoding="utf-8")
        env_path.write_text("", encoding="utf-8")
        return GarakRunArtifacts(
            artifact_dir=str(Path(artifact_dir)),
            report_prefix=str(report_prefix),
            command=command,
            exit_code=0,
            runtime_seconds=3.0,
            timed_out=False,
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            command_path=str(command_path),
            runtime_metadata_path=str(runtime_path),
            environment_path=str(env_path),
            jsonl_reports=[str(jsonl_dest)],
            html_reports=[str(html_dest)],
            hitlog_reports=[],
        )

    with patch("modelguard.orchestration.scan_orchestrator.run_garak", side_effect=fake_run_garak), patch(
        "modelguard.config._local_filename_timestamp", return_value="2026-05-15_20-34-21"
    ):
        exit_code = main(
            [
                "scan",
                "--config",
                "configs/local-ollama-garak.yaml",
                "--out",
                str(tmp_path / "reports" / "scan.md"),
            ]
        )

    assert exit_code == 0
    json_report = tmp_path / "reports" / "scan.json"
    md_report = tmp_path / "reports" / "scan.md"
    html_report = tmp_path / "reports" / "scan.html"
    assert json_report.exists()
    assert md_report.exists()
    assert html_report.exists()
    payload = json.loads(json_report.read_text(encoding="utf-8"))
    assert payload["scan"]["scanner"] == "garak"
    assert payload["evidence"]["jsonl_reports"]
    assert payload["results"][0]["probe_id"] == "test.Test"
