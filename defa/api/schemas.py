"""
schemas.py — Pydantic Request & Response Models for DEFA 2.0 API
"""

from typing import Any
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    directory: str | None = Field(default=None, description="Directory path to scan")
    items: list[str] | None = Field(default=None, description="List of dynamic files or folders to scan")
    output_dir: str = Field(default="reports", description="Output folder for reports")


class EvidencePreviewRequest(BaseModel):
    items: list[str] = Field(..., description="List of file or directory paths to inspect")


class InvestigateRequest(BaseModel):
    items: list[str] = Field(..., description="List of file or directory paths to investigate")
    output_dir: str = Field(default="reports", description="Output folder for reports")


class VerifyRequest(BaseModel):
    directory: str = Field(..., description="Directory path to verify")
    baseline_path: str = Field(default="reports/baseline.json", description="Path to baseline.json")
    output_dir: str = Field(default="reports", description="Output folder for verification report")


class ChatMessage(BaseModel):
    role: str = Field(..., description="'user', 'assistant', or 'system'")
    content: str = Field(..., description="Message text")


class ChatRequest(BaseModel):
    messages: list[ChatMessage] = Field(..., description="Conversation history")
    model: str | None = Field(default=None, description="Optional Ollama model override")


class SettingsModel(BaseModel):
    ollama_url: str = "http://localhost:11434"
    default_model: str = "llama3.2"
    ai_enabled: bool = True
    theme: str = "dark"
    reports_dir: str = "reports"


class CompareRequest(BaseModel):
    older_id: str
    newer_id: str
