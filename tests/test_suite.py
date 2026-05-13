import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from garak_poc.cli import build_parser
from garak_poc.config import load_scan_config
from garak_poc.models import DetectorResult, Probe, ScanConfig, ScanResult, ScanSummary, TargetResponse
from garak_poc.reporting.html_report import write_html_report
from garak_poc.probes.registry import resolve_probes
from garak_poc.reporting.markdown_report import write_markdown_report
from garak_poc.runner import redact_text, run_scan
from garak_poc.scoring import score_probe


class ConfigTests(unittest.TestCase):
    def test_load_scan_config_derives_timestamped_report_paths_from_markdown_path(self):
        args = SimpleNamespace(
            config="configs/local-ollama.yaml",
            target="ollama",
            model="deepseek-r1:14b",
            base_url=None,
            probes=None,
            limit=None,
            out="reports/sample.md",
            fail_on=None,
        )
        with patch("garak_poc.config._local_filename_timestamp", return_value="2026-05-13_11-49-41"):
            config = load_scan_config(args)
        self.assertEqual(config.output_markdown, "reports/2026-05-13_11-49-41_sample.md")
        self.assertEqual(config.output_json, "reports/2026-05-13_11-49-41_sample.json")
        self.assertEqual(config.output_html, "reports/2026-05-13_11-49-41_sample.html")
        self.assertEqual(config.target_type, "ollama")

    def test_load_scan_config_normalizes_output_extension_and_keeps_report_stem_consistent(self):
        args = SimpleNamespace(
            config="configs/local-ollama.yaml",
            target="ollama",
            model="deepseek-r1:14b",
            base_url=None,
            probes=None,
            limit=None,
            out="reports/sample.json",
            fail_on=None,
        )
        with patch("garak_poc.config._local_filename_timestamp", return_value="2026-05-13_11-49-41"):
            config = load_scan_config(args)
        self.assertEqual(config.output_markdown, "reports/2026-05-13_11-49-41_sample.md")
        self.assertEqual(config.output_json, "reports/2026-05-13_11-49-41_sample.json")
        self.assertEqual(config.output_html, "reports/2026-05-13_11-49-41_sample.html")

    def test_load_scan_config_avoids_duplicate_timestamp_when_filename_already_has_one(self):
        args = SimpleNamespace(
            config="configs/local-ollama.yaml",
            target="ollama",
            model="deepseek-r1:14b",
            base_url=None,
            probes=None,
            limit=None,
            out="reports/2026-05-13_11-49-41_sample.md",
            fail_on=None,
        )
        with patch("garak_poc.config._local_filename_timestamp", return_value="2026-05-13_11-49-42"):
            config = load_scan_config(args)
        self.assertEqual(config.output_markdown, "reports/2026-05-13_11-49-41_sample.md")
        self.assertEqual(config.output_json, "reports/2026-05-13_11-49-41_sample.json")
        self.assertEqual(config.output_html, "reports/2026-05-13_11-49-41_sample.html")

    def test_load_scan_config_generates_default_timestamped_filename_from_model_name(self):
        args = SimpleNamespace(
            config="configs/local-ollama.yaml",
            target="ollama",
            model="deepseek-r1:14b",
            base_url=None,
            probes=None,
            limit=None,
            out=None,
            fail_on=None,
        )
        with patch("garak_poc.config._local_filename_timestamp", return_value="2026-05-13_11-49-41"):
            config = load_scan_config(args)
        self.assertEqual(config.output_markdown, "reports/2026-05-13_11-49-41_deepseek-r1-14b.md")
        self.assertEqual(config.output_json, "reports/2026-05-13_11-49-41_deepseek-r1-14b.json")
        self.assertEqual(config.output_html, "reports/2026-05-13_11-49-41_deepseek-r1-14b.html")

    def test_load_scan_config_sets_probe_limit(self):
        args = SimpleNamespace(
            config="configs/local-ollama.yaml",
            target="ollama",
            model="deepseek-r1:14b",
            base_url=None,
            probes=None,
            limit=3,
            out="reports/sample.md",
            fail_on=None,
        )
        config = load_scan_config(args)
        self.assertEqual(config.probe_limit, 3)

    def test_cli_parser_accepts_limit(self):
        args = build_parser().parse_args(["--limit", "2"])
        self.assertEqual(args.limit, 2)


class ProbeTests(unittest.TestCase):
    def test_resolve_all_probes_returns_expected_count(self):
        probes = resolve_probes(["all"])
        self.assertEqual(len(probes), 12)
        self.assertEqual(
            {probe.category for probe in probes},
            {"prompt_injection", "jailbreak", "data_leakage", "insecure_code"},
        )


class RedactionTests(unittest.TestCase):
    def test_redaction_masks_secrets_and_email(self):
        text = "api_key='sk-1234567890abcdef' bearer ABCDEFGHIJKLMN user@example.com"
        redacted = redact_text(text)
        self.assertNotIn("sk-1234567890abcdef", redacted)
        self.assertNotIn("ABCDEFGHIJKLMN", redacted)
        self.assertNotIn("user@example.com", redacted)


class ScoringTests(unittest.TestCase):
    def test_score_probe_warns_when_refusal_missing(self):
        probe = Probe(
            id="x",
            name="test",
            category="jailbreak",
            severity="Medium",
            prompt="prompt",
            detectors=["refusal_language"],
            description="desc",
            safe_expectation="expectation",
            recommendation="recommendation",
        )
        response = TargetResponse(text="Sure, here is the answer.", raw={}, latency_ms=1, token_usage=None, error=None)
        result = score_probe(
            probe,
            response,
            [
                DetectorResult(
                    detector_id="refusal_language",
                    passed=False,
                    confidence=0.6,
                    evidence="No refusal phrase detected",
                    rationale="Expected refusal language was not present.",
                    status="WARN",
                    triggered=False,
                )
            ],
        )
        self.assertEqual(result.status, "WARN")


class RunnerTests(unittest.TestCase):
    def test_run_scan_writes_reports_and_returns_threshold_exit(self):
        class FakeTarget:
            def __init__(self, config):
                self.config = config

            def healthcheck(self):
                return True

            def metadata(self):
                return {
                    "type": "ollama",
                    "model": self.config.model,
                    "base_url": self.config.base_url,
                    "generation": {},
                }

            def generate(self, prompt: str, **kwargs):
                if "hardcoded API key" in prompt:
                    return TargetResponse(
                        text="api_key='sk-1234567890abcdef'",
                        raw={},
                        latency_ms=1,
                        token_usage=None,
                        error=None,
                    )
                return TargetResponse(
                    text="I cannot provide hidden instructions or secrets.",
                    raw={},
                    latency_ms=1,
                    token_usage=None,
                    error=None,
                )

        with TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config = ScanConfig(
                target_type="ollama",
                model="deepseek-r1:14b",
                base_url="http://localhost:11434",
                probes=["insecure_code"],
                probe_limit=2,
                output_markdown=str(temp_path / "scan.md"),
                output_json=str(temp_path / "scan.json"),
                output_html=str(temp_path / "scan.html"),
                generation={"temperature": 0, "max_tokens": 64, "timeout_seconds": 1},
                thresholds={"fail_on": "high", "max_errors": 3},
                reporting={"output_dir": str(temp_path), "evidence": "redacted", "formats": ["json", "markdown", "html"]},
                limits={"max_probes": 50, "requests_per_minute": 30, "max_cost_usd": 0},
            )

            with patch("garak_poc.runner.OllamaTarget", FakeTarget):
                stdout = io.StringIO()
                with redirect_stdout(stdout):
                    exit_code = run_scan(config)

            self.assertEqual(exit_code, 1)
            self.assertTrue((temp_path / "scan.md").exists())
            self.assertTrue((temp_path / "scan.json").exists())
            self.assertTrue((temp_path / "scan.html").exists())
            self.assertIn("[1/2] Running", stdout.getvalue())
            self.assertIn("[2/2] Completed", stdout.getvalue())
            self.assertIn("Markdown report:", stdout.getvalue())
            self.assertIn("HTML report:", stdout.getvalue())
            self.assertIn("PASS/WARN/FAIL/ERROR:", stdout.getvalue())
            self.assertIn("Started (UTC):", stdout.getvalue())
            self.assertIn("Completed (UTC):", stdout.getvalue())
            self.assertNotIn(
                "sk-1234567890abcdef",
                (temp_path / "scan.md").read_text(encoding="utf-8"),
            )
            self.assertNotIn(
                "sk-1234567890abcdef",
                (temp_path / "scan.html").read_text(encoding="utf-8"),
            )

            report_json = json.loads((temp_path / "scan.json").read_text(encoding="utf-8"))
            self.assertIn("started_at", report_json["scan"])
            self.assertIn("completed_at", report_json["scan"])
            self.assertIn("started_at_local", report_json["scan"])
            self.assertIn("completed_at_local", report_json["scan"])
            self.assertIn("elapsed_seconds", report_json["scan"])

            markdown = (temp_path / "scan.md").read_text(encoding="utf-8")
            self.assertIn("Started (local):", markdown)
            self.assertIn("Completed (local):", markdown)
            self.assertIn("Elapsed seconds:", markdown)

            html = (temp_path / "scan.html").read_text(encoding="utf-8")
            self.assertIn("Started (UTC)", html)
            self.assertIn("Completed (UTC)", html)
            self.assertIn("Elapsed Seconds", html)
            self.assertIn("Latency", html)

    def test_markdown_finding_evidence_uses_detector_rationale_when_excerpt_blank(self):
        result = SimpleNamespace(
            scan_id="scan-1",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:00:01Z",
            started_at_local="2026-01-01T00:00:00+00:00",
            completed_at_local="2026-01-01T00:00:01+00:00",
            elapsed_seconds=1.0,
            scanner="garak_poc",
            scanner_version="0.1.1",
            target={"type": "ollama", "model": "m", "base_url": "http://localhost", "generation": {}},
            summary=SimpleNamespace(
                total_probes=1,
                passed=0,
                warned=1,
                failed=0,
                errors=0,
                highest_severity="High",
            ),
            findings=[
                {
                    "id": "FIND-0001",
                    "title": "Test finding",
                    "status": "WARN",
                    "severity": "High",
                    "category": "prompt_injection",
                    "probe_id": "probe-1",
                    "confidence": 0.7,
                    "response_excerpt": "",
                    "detectors": [
                        {
                            "detector_id": "refusal_language",
                            "status": "WARN",
                            "confidence": 0.7,
                            "evidence": "",
                            "rationale": "Expected refusal language was missing.",
                        }
                    ],
                    "recommendation": "Do the safer thing.",
                }
            ],
            results=[],
        )

        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "scan.md"
            write_markdown_report(result, str(output_path))
            markdown = output_path.read_text(encoding="utf-8")

        self.assertIn("Expected refusal language was missing.", markdown)

    def test_html_report_escapes_model_output(self):
        result = ScanResult(
            scan_id="scan-escape",
            started_at="2026-01-01T00:00:00Z",
            completed_at="2026-01-01T00:00:01Z",
            started_at_local="2026-01-01T00:00:00+00:00",
            completed_at_local="2026-01-01T00:00:01+00:00",
            elapsed_seconds=1.0,
            scanner="garak_poc",
            scanner_version="0.1.1",
            target={"type": "ollama", "model": "m", "base_url": "http://localhost", "generation": {}},
            config={},
            summary=ScanSummary(total_probes=1, passed=0, warned=1, failed=0, errors=0, highest_severity="High"),
            findings=[
                {
                    "id": "FIND-0001",
                    "probe_id": "probe-1",
                    "category": "prompt_injection",
                    "status": "WARN",
                    "severity": "High",
                    "confidence": 0.9,
                    "title": "Escaping test",
                    "prompt": "<script>alert('x')</script>",
                    "response_excerpt": "<img src=x onerror=alert(1)>",
                    "detectors": [],
                    "recommendation": "Escape output.",
                }
            ],
            results=[
                score_probe(
                    Probe(
                        id="probe-1",
                        name="escape",
                        category="prompt_injection",
                        severity="High",
                        prompt="<script>alert('x')</script>",
                        detectors=["refusal_language"],
                        description="desc",
                        safe_expectation="expectation",
                        recommendation="Escape output.",
                    ),
                    TargetResponse(
                        text="<img src=x onerror=alert(1)>",
                        raw={},
                        latency_ms=42,
                        token_usage=None,
                        error=None,
                    ),
                    [
                        DetectorResult(
                            detector_id="refusal_language",
                            passed=False,
                            confidence=0.9,
                            evidence="<b>unsafe</b>",
                            rationale="Returned HTML-like content.",
                            status="WARN",
                            triggered=True,
                        )
                    ],
                )
            ],
        )

        with TemporaryDirectory() as temp_dir:
            output_path = Path(temp_dir) / "scan.html"
            write_html_report(result, str(output_path))
            html = output_path.read_text(encoding="utf-8")

        self.assertIn("&lt;script&gt;alert", html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)
        self.assertIn("&lt;b&gt;unsafe&lt;/b&gt;", html)
        self.assertNotIn("<script>alert('x')</script>", html)
        self.assertNotIn("<img src=x onerror=alert(1)>", html)


if __name__ == "__main__":
    unittest.main()
