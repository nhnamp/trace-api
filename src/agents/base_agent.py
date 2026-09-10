from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from src.config.settings import LLMProviderConfig
from src.llm.client import LLMClient
from src.llm.logger import LLMLogger


class BaseAgent(ABC):
    def __init__(
        self,
        llm_config: LLMProviderConfig,
        llm_logger: LLMLogger | None = None,
    ):
        self.llm_client = LLMClient(llm_config, llm_logger)

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    async def run(self, input_data: Any) -> Any:
        ...
