import asyncio
import json
import logging
from abc import ABC, abstractmethod

import google.generativeai as genai

from app.config import settings

logger = logging.getLogger(__name__)

GEMINI_SEMAPHORE = asyncio.Semaphore(3)

_configured = False


def _ensure_configured() -> None:
    global _configured
    if not _configured and settings.gemini_api_key:
        genai.configure(api_key=settings.gemini_api_key)
        _configured = True


class BaseAgent(ABC):
    def __init__(self, model: genai.GenerativeModel | None = None):
        _ensure_configured()
        self._model = model or genai.GenerativeModel(
            "gemini-1.5-pro",
            generation_config=genai.GenerationConfig(
                response_mime_type="application/json",
            ),
        )

    @abstractmethod
    async def analyze(self, context: dict) -> dict:
        ...

    async def _call_gemini(self, prompt: str) -> dict:
        max_retries = 3
        for attempt in range(max_retries):
            try:
                async with GEMINI_SEMAPHORE:
                    response = await asyncio.to_thread(
                        self._model.generate_content, prompt
                    )
                text = response.text if response and response.text else "{}"
                text = text.strip()
                if text.startswith("```"):
                    text = text.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
                return json.loads(text)
            except json.JSONDecodeError:
                return {"error": True, "raw_response": text}
            except Exception as exc:
                logger.warning(
                    "Gemini call attempt %d/%d failed: %s",
                    attempt + 1, max_retries, exc,
                )
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
                else:
                    return {"error": True, "raw_response": str(exc)}
        return {"error": True, "raw_response": "Max retries exceeded"}
