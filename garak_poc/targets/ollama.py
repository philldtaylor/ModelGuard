from __future__ import annotations

from time import perf_counter

import requests

from garak_poc.models import ScanConfig, TargetResponse
from garak_poc.targets.base import BaseTarget


class OllamaTarget(BaseTarget):
    def __init__(self, config: ScanConfig):
        self.config = config
        self.endpoint = f"{config.base_url.rstrip('/')}/api/generate"

    def healthcheck(self) -> bool:
        probe = self.generate("Reply with the single word OK.", max_tokens=8)
        return probe.error is None

    def metadata(self) -> dict:
        return {
            "type": "ollama",
            "model": self.config.model,
            "base_url": self.config.base_url,
            "generation": {
                "temperature": self.config.generation["temperature"],
                "max_tokens": self.config.generation["max_tokens"],
            },
        }

    def generate(self, prompt: str, **kwargs) -> TargetResponse:
        payload = {
            "model": self.config.model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", self.config.generation["temperature"]),
                "num_predict": kwargs.get("max_tokens", self.config.generation["max_tokens"]),
            },
        }
        timeout = kwargs.get("timeout_seconds", self.config.generation["timeout_seconds"])
        start = perf_counter()
        try:
            response = requests.post(self.endpoint, json=payload, timeout=timeout)
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            latency_ms = int((perf_counter() - start) * 1000)
            return TargetResponse(text="", raw=None, latency_ms=latency_ms, token_usage=None, error=str(exc))
        latency_ms = int((perf_counter() - start) * 1000)
        return TargetResponse(
            text=str(data.get("response", "")),
            raw=data,
            latency_ms=latency_ms,
            token_usage={
                "prompt_eval_count": data.get("prompt_eval_count"),
                "eval_count": data.get("eval_count"),
            },
            error=None,
        )
