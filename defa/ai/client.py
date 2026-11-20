"""
client.py — Local Ollama API Client

Responsibility:
    Communicate with local Ollama instance (http://localhost:11434).
    No cloud AI, no paid APIs, no API keys, no file uploads.
    Gracefully handles offline states with setup guidance.
"""

import json
import logging
import socket
import urllib.parse
import urllib.request
import urllib.error
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.2"
REQUEST_TIMEOUT_SECONDS = 30.0


class OllamaClient:
    """
    Client for interacting with locally running Ollama server.
    Uses standard library urllib to avoid extra dependencies, with robust timeout.
    """

    def __init__(self, base_url: str = DEFAULT_OLLAMA_URL, default_model: str = DEFAULT_MODEL):
        self.base_url = base_url.rstrip("/")
        self.default_model = default_model

    def _is_port_reachable(self, timeout: float = 0.5) -> bool:
        """Rapid pre-check to verify if server port is open and listening."""
        try:
            parsed = urllib.parse.urlparse(self.base_url)
            host = parsed.hostname or "127.0.0.1"
            port = parsed.port or 11434
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            res = sock.connect_ex((host, port))
            sock.close()
            return res == 0
        except Exception:
            return False

    def check_health(self) -> dict[str, Any]:
        """
        Check if local Ollama daemon is reachable.

        Returns:
            dict with 'online' (bool), 'version' (str or None), and 'error' (str or None).
        """
        if not self._is_port_reachable():
            return {
                "online": False,
                "version": None,
                "base_url": self.base_url,
                "error": "Ollama service is not reachable at " + self.base_url,
            }

        url = f"{self.base_url}/api/version"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DEFA-Forensics/2.0"})
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return {
                        "online": True,
                        "version": data.get("version", "unknown"),
                        "base_url": self.base_url,
                        "error": None,
                    }
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            logger.debug("Ollama health check failed: %s", exc)

        return {
            "online": False,
            "version": None,
            "base_url": self.base_url,
            "error": "Ollama service is not reachable at " + self.base_url,
        }

    def list_models(self) -> list[str]:
        """
        List all locally pulled models in Ollama.

        Returns:
            List of model name strings (e.g., ['llama3.2:latest', 'mistral:latest']).
        """
        url = f"{self.base_url}/api/tags"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "DEFA-Forensics/2.0"})
            with urllib.request.urlopen(req, timeout=4.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    models = data.get("models", [])
                    return [m.get("name") for m in models if m.get("name")]
        except Exception as exc:
            logger.debug("Failed to list Ollama models: %s", exc)
        return []

    def chat(
        self,
        messages: list[dict[str, str]],
        model: str | None = None,
        system_prompt: str | None = None,
    ) -> dict[str, Any]:
        """
        Send a conversation history to Ollama's /api/chat endpoint.

        Args:
            messages: List of dicts with 'role' ('user'|'assistant'|'system') and 'content'.
            model: Model name to use (defaults to self.default_model).
            system_prompt: Optional prepended system instruction.

        Returns:
            dict with 'success' (bool), 'reply' (str), 'model' (str), 'error' (str or None).
        """
        chosen_model = model or self.default_model
        health = self.check_health()
        if not health["online"]:
            return {
                "success": False,
                "reply": "",
                "model": chosen_model,
                "error": (
                    "Ollama is not running. Please ensure Ollama is installed and active on "
                    f"{self.base_url}. Start it with `ollama serve`."
                ),
            }

        url = f"{self.base_url}/api/chat"
        payload_messages = []
        if system_prompt:
            payload_messages.append({"role": "system", "content": system_prompt})

        payload_messages.extend(messages)

        payload = {
            "model": chosen_model,
            "messages": payload_messages,
            "stream": False,
            "options": {
                "temperature": 0.2,  # Low temperature for factual forensic precision
            },
        }

        try:
            req_data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url,
                data=req_data,
                headers={"Content-Type": "application/json", "User-Agent": "DEFA-Forensics/2.0"},
            )
            with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT_SECONDS) as resp:
                if resp.status == 200:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    msg = resp_data.get("message", {})
                    reply_text = msg.get("content", "")
                    return {
                        "success": True,
                        "reply": reply_text.strip(),
                        "model": chosen_model,
                        "error": None,
                    }
                else:
                    return {
                        "success": False,
                        "reply": "",
                        "model": chosen_model,
                        "error": f"Ollama HTTP error {resp.status}",
                    }
        except urllib.error.HTTPError as exc:
            try:
                err_detail = exc.read().decode("utf-8")
            except Exception:
                err_detail = str(exc)
            return {
                "success": False,
                "reply": "",
                "model": chosen_model,
                "error": f"Ollama error: {err_detail}",
            }
        except Exception as exc:
            logger.error("Error communicating with Ollama: %s", exc)
            return {
                "success": False,
                "reply": "",
                "model": chosen_model,
                "error": f"Failed to communicate with Ollama: {exc}",
            }
