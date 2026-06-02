from __future__ import annotations
import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Callable

logger = logging.getLogger(__name__)


SSEEvent = dict[str, Any]


def make_event(agent: str, status: str, message: str) -> SSEEvent:
    return {
        "agent": agent,
        "status": status,
        "message": message,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


class BaseAgent(ABC):
    name: str = "BASE"

    def __init__(
        self,
        on_event: Callable[[SSEEvent], None] | None = None,
        config: dict | None = None,
    ):
        self.on_event = on_event or (lambda e: None)
        self.config = config or {}
        self.findings: list[dict] = []
        self.output: dict = {}

    def emit(self, status: str, message: str):
        event = make_event(self.name, status, message)
        self.on_event(event)
        level = "ERROR" if status == "error" else "INFO"
        logger.info(f"[{self.name}] [{level}] {message}")

    def emit_running(self, message: str):
        self.emit("running", message)

    def emit_complete(self, message: str):
        self.emit("complete", message)

    def emit_error(self, message: str):
        self.emit("error", message)

    def add_finding(self, finding: dict):
        finding.setdefault("agent", self.name)
        self.findings.append(finding)

    @abstractmethod
    async def run(self, context: dict) -> dict:
        ...


class GroqAgent(BaseAgent):
    groq_model: str = "llama-3.3-70b-versatile"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._groq_client = None

    def _get_groq_client(self):
        if self._groq_client is not None:
            return self._groq_client
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            return None
        try:
            from groq import Groq
            self._groq_client = Groq(api_key=api_key)
        except Exception as e:
            logger.warning(f"Groq client init failed: {e}")
            self._groq_client = None
        return self._groq_client

    def _call_groq(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.3,
    ) -> str | None:
        client = self._get_groq_client()
        if not client:
            self.emit_error("GROQ_API_KEY not set or Groq unavailable")
            return None
        try:
            resp = client.chat.completions.create(
                model=self.groq_model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=temperature,
                max_tokens=4096,
                response_format={"type": "json_object"},
            )
            return resp.choices[0].message.content
        except Exception as e:
            self.emit_error(f"Groq call failed: {e}")
            return None

    def _parse_json(self, text: str | None) -> dict | None:
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            try:
                start = text.index("{")
                end = text.rindex("}") + 1
                return json.loads(text[start:end])
            except (ValueError, json.JSONDecodeError):
                self.emit_error(f"Failed to parse JSON from Groq response")
                return None
