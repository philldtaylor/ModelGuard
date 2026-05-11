from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from garak_poc.config import load_scan_config
from garak_poc.models import DetectorResult, Probe, ScanConfig, TargetResponse
from garak_poc.probes.registry import resolve_probes
from garak_poc.runner import redact_text, run_scan
from garak_poc.scoring import score_probe


class ConfigTests(unittest.TestCase):
    def test_load_scan_config_derives_json_from_markdown_path(self):
        args = SimpleNamespace(
            config="configs/local-ollama.yaml",
            target="ollama",
            model="deepseek-r1:14b",
            base_url=None,
            probes=None,
            out="reports/sample.md",
            fail_on=None,
        )
        config = load_scan_config(args)
        self.assertEqual(config.output_markdown, "reports/sample.md")
        self.assertEqual(config.output_json, "reports/sample.json")
        self.assertEqual(config.target_type, "ollama")


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
                probes=["all"],
                output_markdown=str(temp_path / "scan.md"),
                output_json=str(temp_path / "scan.json"),
                generation={"temperature": 0, "max_tokens": 64, "timeout_seconds": 1},
                thresholds={"fail_on": "high", "max_errors": 3},
                reporting={"output_dir": str(temp_path), "evidence": "redacted", "formats": ["json", "markdown"]},
                limits={"max_probes": 50, "requests_per_minute": 30, "max_cost_usd": 0},
            )

            with patch("garak_poc.runner.OllamaTarget", FakeTarget):
                exit_code = run_scan(config)

            self.assertEqual(exit_code, 1)
            self.assertTrue((temp_path / "scan.md").exists())
            self.assertTrue((temp_path / "scan.json").exists())
            self.assertNotIn(
                "sk-1234567890abcdef",
                (temp_path / "scan.md").read_text(encoding="utf-8"),
            )


if __name__ == "__main__":
    unittest.main()
