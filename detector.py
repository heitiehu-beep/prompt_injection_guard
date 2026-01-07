"""
Prompt Injection Detector
"""

import re
import json
import aiohttp
from typing import Optional, Tuple, List, Dict, Any

from src.common.logger import get_logger
from src.plugin_system.apis import llm_api

from .rules import (
    ALL_KEYWORDS,
    PRESET_PATTERNS,
    KEYWORD_CATEGORIES,
    PATTERN_CATEGORIES,
    LLM_DETECTION_PROMPT,
    LLM_BATCH_DETECTION_PROMPT,
)

logger = get_logger("prompt_injection_guard")


class CustomLLMClient:
    """自定义 OpenAI 格式 API"""

    def __init__(self, api_base: str, api_key: str, model: str):
        self.api_base = api_base.rstrip("/")
        self.api_key = api_key
        self.model = model

    async def generate(self, prompt: str, temperature: float = 0.1, max_tokens: int = 50) -> Optional[str]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.api_base}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "Content-Type": "application/json",
                    },
                    json={
                        "model": self.model,
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": temperature,
                        "max_tokens": max_tokens,
                    },
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status != 200:
                        return None
                    data = await resp.json()
                    return data["choices"][0]["message"]["content"]
        except Exception as e:
            logger.error(f"API error: {e}")
            return None


class InjectionDetector:

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.keywords: List[str] = []
        self.patterns: List[str] = []
        self._load_rules()

        self.compiled_patterns: List[Tuple[re.Pattern, str]] = []
        for pattern in self.patterns:
            try:
                compiled = re.compile(pattern)
                category = PATTERN_CATEGORIES.get(pattern, "自定义")
                self.compiled_patterns.append((compiled, category))
            except re.error:
                pass

        self.custom_llm_client: Optional[CustomLLMClient] = None
        if config.get("llm", {}).get("source") == "custom":
            custom = config.get("llm", {}).get("custom", {})
            if custom.get("api_base") and custom.get("api_key"):
                self.custom_llm_client = CustomLLMClient(
                    api_base=custom["api_base"],
                    api_key=custom["api_key"],
                    model=custom.get("model", "gpt-4o-mini"),
                )

    def _load_rules(self):
        rules = self.config.get("rules", {})

        if rules.get("enable_preset_rules", True):
            self.keywords = ALL_KEYWORDS.copy()
            self.patterns = PRESET_PATTERNS.copy()
            logger.info(f"[Injection] 加载 {len(self.keywords)} 关键词, {len(self.patterns)} 正则")

        custom_kw = rules.get("custom_keywords", [])
        custom_pt = rules.get("custom_patterns", [])
        if custom_kw:
            self.keywords.extend(custom_kw)
        if custom_pt:
            self.patterns.extend(custom_pt)

    def rule_check(self, text: str) -> Optional[Tuple[str, str, int]]:
        """规则检测，返回 (命中规则, 类别, 命中数量) 或 None"""
        text_lower = text.lower()
        min_hits = self.config.get("detection", {}).get("min_rule_hits", 1)

        hits = []  # (规则, 类别)

        for keyword in self.keywords:
            if keyword.lower() in text_lower:
                category = KEYWORD_CATEGORIES.get(keyword.lower(), "自定义")
                hits.append((keyword, category))

        for compiled, category in self.compiled_patterns:
            if compiled.search(text):
                hits.append((compiled.pattern, category))

        if len(hits) >= min_hits:
            return (hits[0][0], hits[0][1], len(hits))

        return None

    async def llm_check(self, text: str) -> Tuple[bool, str]:
        """单条 LLM 检测"""
        prompt = LLM_DETECTION_PROMPT.format(message=text)
        llm_config = self.config.get("llm", {})
        settings = llm_config.get("settings", {})
        temperature = settings.get("temperature", 0.1)
        max_tokens = settings.get("max_tokens", 150)

        result: Optional[str] = None

        if self.custom_llm_client:
            result = await self.custom_llm_client.generate(prompt, temperature, max_tokens)
        else:
            model_name = llm_config.get("main_model_name", "replyer")
            models = llm_api.get_available_models()
            model_config = models.get(model_name)

            if not model_config:
                return False, "未找到模型"

            success, content, _, _ = await llm_api.generate_with_model(
                prompt=prompt,
                model_config=model_config,
                request_type="prompt_injection_detection",
                temperature=temperature,
                max_tokens=max_tokens,
            )
            if success:
                result = content

        if result:
            result = result.strip()
            try:
                json_match = re.search(r'\{[^{}]*"is_injection"[^{}]*\}', result, re.DOTALL)
                if json_match:
                    data = json.loads(json_match.group())
                    return bool(data.get("is_injection", False)), data.get("reason", "")
                elif "true" in result.lower():
                    return True, "检测到 true"
            except json.JSONDecodeError:
                if "true" in result.lower():
                    return True, "检测到 true"

        return False, ""

    async def batch_llm_check(
        self,
        chat_history: List[Dict[str, str]],
        suspects: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """批量 LLM 检测"""
        if not suspects:
            return []

        history_lines = [f"{m['user']}: {m['text']}" for m in chat_history[-30:]]
        suspect_lines = [f"[{i}] {s['user']}: {s['text']}" for i, s in enumerate(suspects)]

        prompt = LLM_BATCH_DETECTION_PROMPT.format(
            chat_history="\n".join(history_lines),
            suspect_count=len(suspects),
            suspect_messages="\n".join(suspect_lines),
        )

        llm_config = self.config.get("llm", {})
        settings = llm_config.get("settings", {})
        temperature = settings.get("temperature", 0.1)
        max_tokens = max(settings.get("max_tokens", 100), 50 * len(suspects) + 100)

        result: Optional[str] = None

        if self.custom_llm_client:
            result = await self.custom_llm_client.generate(prompt, temperature, max_tokens)
        else:
            model_name = llm_config.get("main_model_name", "replyer")
            models = llm_api.get_available_models()
            model_config = models.get(model_name)

            if not model_config:
                return suspects  # fallback

            success, content, _, _ = await llm_api.generate_with_model(
                prompt=prompt,
                model_config=model_config,
                request_type="prompt_injection_detection",
                temperature=temperature,
                max_tokens=max_tokens,
            )
            if success:
                result = content

        if not result:
            return suspects

        confirmed = []
        try:
            json_match = re.search(r'\{[^{}]*"results"[^{}]*\[.*?\][^{}]*\}', result, re.DOTALL)
            if json_match:
                data = json.loads(json_match.group())
                for r in data.get("results", []):
                    idx = r.get("index", -1)
                    if r.get("is_injection") and 0 <= idx < len(suspects):
                        suspect = suspects[idx].copy()
                        suspect["llm_reason"] = r.get("reason", "")
                        confirmed.append(suspect)
            else:
                if '"is_injection": true' in result.lower():
                    return suspects
        except json.JSONDecodeError:
            return suspects

        return confirmed

    async def detect(self, text: str) -> Optional[Tuple[str, str, str]]:
        """单条检测，返回 (规则, 类别, 方式, 命中数) 或 None"""
        mode = self.config.get("detection", {}).get("mode", "rule_then_llm")

        if mode == "rule_only":
            result = self.rule_check(text)
            if result:
                return (result[0], result[1], "规则", result[2])
            return None

        elif mode == "rule_then_llm":
            result = self.rule_check(text)
            if result:
                is_injection, reason = await self.llm_check(text)
                if is_injection:
                    return (result[0], result[1], "规则+LLM", result[2])
            return None

        elif mode == "llm_only":
            is_injection, reason = await self.llm_check(text)
            if is_injection:
                return ("LLM", reason, "LLM", 1)
            return None

        return None
