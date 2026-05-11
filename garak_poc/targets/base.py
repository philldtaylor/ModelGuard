from __future__ import annotations

from garak_poc.models import TargetResponse


class BaseTarget:
    def healthcheck(self) -> bool:
        raise NotImplementedError

    def metadata(self) -> dict:
        raise NotImplementedError

    def generate(self, prompt: str, **kwargs) -> TargetResponse:
        raise NotImplementedError
