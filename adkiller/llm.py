"""Universal OpenAI-compatible single-model LLM client with automatic multimodal probing & token tracking."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlparse

from openai import AsyncOpenAI
from PIL import Image

from .prompts import SYSTEM_PROMPT

logger = logging.getLogger("adkiller.llm")


@dataclass
class SpamVerdict:
    is_spam: bool
    score: int
    reason: str
    used_vision: bool = False
    prompt_tokens: int = 0
    completion_tokens: int = 0
    cached_tokens: int = 0


@dataclass
class ProbeReport:
    text_ok: bool
    vision_supported: bool
    text_detail: str
    vision_detail: str


def _make_probe_jpeg_data_url() -> str:
    """Generate a tiny 32x32 orange JPEG in memory for zero-dependency vision probing."""
    img = Image.new("RGB", (32, 32), color=(255, 140, 0))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=75)
    b64 = base64.b64encode(buf.getvalue()).decode("ascii")
    return f"data:image/jpeg;base64,{b64}"


def _extract_usage(resp: Any) -> tuple[int, int, int]:
    """Extract (prompt_tokens, completion_tokens, cached_tokens) across OpenAI & DeepSeek formats."""
    usage = getattr(resp, "usage", None)
    if not usage:
        return 0, 0, 0
    prompt_tokens = int(getattr(usage, "prompt_tokens", 0) or 0)
    completion_tokens = int(getattr(usage, "completion_tokens", 0) or 0)

    cached_tokens = int(getattr(usage, "prompt_cache_hit_tokens", 0) or 0)
    if not cached_tokens:
        details = getattr(usage, "prompt_tokens_details", None)
        if details:
            cached_tokens = int(getattr(details, "cached_tokens", 0) or 0)
    return prompt_tokens, completion_tokens, cached_tokens


def parse_verdict_json(raw_text: str) -> tuple[bool, int, str]:
    """Strict JSON parser: raises ValueError on empty or malformed output so caller falls back cleanly."""
    text = (raw_text or "").strip()
    if not text:
        raise ValueError("模型返回空响应")

    start_brace = text.find("{")
    end_brace = text.rfind("}")
    if start_brace == -1 or end_brace <= start_brace:
        raise ValueError("模型未返回 JSON 对象")
    text = text[start_brace : end_brace + 1]

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("模型返回损坏 JSON") from exc

    if not isinstance(data, dict):
        raise ValueError("模型返回的 JSON 不是对象类型")
    if "state" not in data and "is_spam" not in data and "spam_score" not in data:
        raise ValueError("模型返回的 JSON 缺少必需裁决字段")

    state = data.get("state", 0)
    is_spam = bool(state == 1 or state is True or data.get("is_spam") is True)
    try:
        score = int(round(float(data.get("spam_score", 100 if is_spam else 0))))
    except (TypeError, ValueError) as exc:
        raise ValueError("模型返回无效 spam_score") from exc
    score = max(0, min(100, score))
    reason = str(data.get("spam_reason") or data.get("reason") or "AI 判定为广告").strip()[:120]
    return is_spam, score, reason


_LOCAL_HTTP_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "host.docker.internal"})


def validate_ai_base_url(raw: str) -> Optional[str]:
    """Require HTTPS for all remote endpoints; allow HTTP only on explicit local loopback hosts.

    Rejects embedded userinfo, query parameters, and fragments so URLs never carry embedded secrets.
    """
    val = (raw or "").strip()
    if not val or len(val) > 300 or any(c.isspace() or ord(c) < 32 for c in val):
        return None
    try:
        parsed = urlparse(val)
        _ = parsed.port  # validates numeric port range (0..65535)
    except ValueError:
        return None
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not parsed.hostname
    ):
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname.lower()
    if scheme == "https":
        return val
    if scheme == "http" and host in _LOCAL_HTTP_HOSTS:
        return val
    return None


def sanitize_url_for_display(raw: str) -> str:
    """Return ONLY scheme://host[:port] for logs/UI — never echoes userinfo, path, query, or fragment."""
    val = (raw or "").strip()
    if not val:
        return "(未设置)"
    try:
        parsed = urlparse(val)
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return "(格式无效的地址)"
    if not scheme or not host:
        return "(格式无效的地址)"
    host_disp = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else (80 if scheme == "http" else None)
    if port and port != default_port:
        return f"{scheme}://{host_disp}:{port}"
    return f"{scheme}://{host_disp}"


def url_origin(url: str) -> tuple[str, str, int]:
    """Return normalized (scheme, host, port) origin tuple used to bind credentials to a host."""
    try:
        parsed = urlparse((url or "").strip())
        scheme = (parsed.scheme or "").lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port or (443 if scheme == "https" else (80 if scheme == "http" else 0))
        return scheme, host, port
    except ValueError:
        return "", "", 0


def validate_model_name(raw: str) -> Optional[str]:
    val = (raw or "").strip()
    if not val or len(val) > 120 or any(c.isspace() or ord(c) < 32 for c in val):
        return None
    return val


def validate_api_key(raw: str) -> Optional[str]:
    val = (raw or "").strip()
    if not val or len(val) > 300 or any(c.isspace() or ord(c) < 32 for c in val):
        return None
    return val


_SAFE_REQ_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,48}$")


def format_safe_llm_error(exc: Exception) -> str:
    """Summarize an LLM/network exception using ONLY safe metadata (class, HTTP status, request_id).

    Never logs raw str(exc) so upstream provider bodies, echoed chat text, secret URLs,
    or credential fragments can never leak into logs or admin alerts.
    """
    cls_name = type(exc).__name__
    details: list[str] = []

    status = getattr(exc, "status_code", None)
    if isinstance(status, int) and 100 <= status <= 599:
        details.append(f"HTTP {status}")

    req_id = getattr(exc, "request_id", None)
    if req_id is None:
        resp = getattr(exc, "response", None)
        headers = getattr(resp, "headers", None) if resp is not None else None
        if headers is not None and hasattr(headers, "get"):
            req_id = headers.get("x-request-id") or headers.get("request-id")
    if isinstance(req_id, str) and _SAFE_REQ_ID_RE.match(req_id.strip()):
        details.append(f"req={req_id.strip()}")

    return f"{cls_name} ({', '.join(details)})" if details else cls_name


def mask_api_key(key: str) -> str:
    """Return a safe masked preview of an API key (never exposes raw secrets)."""
    cleaned = (key or "").strip()
    if not cleaned:
        return "未配置"
    if len(cleaned) <= 8:
        return "••••"
    return f"{cleaned[:4]}••••••{cleaned[-4:]}"


class UniversalAIClient:
    """Model-agnostic OpenAI-compatible client: configure ONE model, auto-detect Vision.

    When api_key or model is empty, runs cleanly in disabled mode so basic local rules stay active.
    Supports live hot-reload via reconfigure() without restarting the process.
    """

    def __init__(
        self,
        api_key: str,
        base_url: str,
        model: str,
        *,
        timeout: float = 15.0,
        concurrency: int = 5,
    ):
        self.timeout = timeout
        self.sem = asyncio.Semaphore(concurrency)
        self.client: Any = None
        self.api_key: str = ""
        self.base_url: str = ""
        self.model: str = ""
        self.is_configured: bool = False
        self.text_ready: bool = False
        self.vision_supported: bool = False
        self.vision_note: str = ""
        self.config_warning: str = ""
        self.apply_sync(api_key=api_key, base_url=base_url, model=model)

    def apply_sync(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> Any:
        """Synchronously validate & rebuild internal OpenAI client; returns previous client for optional closing.

        Refuses to construct an API client for any non-compliant base_url (e.g. remote plaintext HTTP),
        falling back cleanly to pure local defense mode with a visible admin warning.
        """
        if api_key is not None:
            self.api_key = api_key.strip()
        if base_url is not None:
            self.base_url = base_url.strip() or "https://api.deepseek.com/v1"
        if model is not None:
            self.model = model.strip()

        old_client = self.client
        self.config_warning = ""
        valid_url = validate_ai_base_url(self.base_url)

        if self.api_key and not valid_url:
            safe_host = sanitize_url_for_display(self.base_url)
            self.config_warning = (
                f"⚠️ 检测到不合规的 AI 接口地址（{safe_host}）：远程接口必须使用 https://"
                "（仅本机回环地址允许 http://，且不可含账号密码或查询参数）。已自动退回纯本地基础防护模式！"
            )
            logger.warning("%s", self.config_warning)
            self.is_configured = False
            self.client = None
        else:
            self.is_configured = bool(self.api_key and self.model and valid_url)
            self.client = (
                AsyncOpenAI(api_key=self.api_key, base_url=valid_url)
                if self.is_configured
                else None
            )

        self.text_ready = False
        self.vision_supported = False
        if self.config_warning:
            self.vision_note = self.config_warning
        else:
            self.vision_note = (
                "未配置大模型（纯本地基础防护模式）" if not self.is_configured else "尚未检测"
            )
        return old_client

    async def reconfigure(
        self,
        *,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        model: Optional[str] = None,
    ) -> None:
        """Hot-reload API credentials/endpoint/model at runtime and gracefully close previous HTTP pool."""
        old_client = self.apply_sync(api_key=api_key, base_url=base_url, model=model)
        if old_client is not None and hasattr(old_client, "close"):
            try:
                await old_client.close()
            except Exception:
                pass

    async def close(self) -> None:
        old_client = self.client
        self.client = None
        if old_client is not None and hasattr(old_client, "close"):
            try:
                await old_client.close()
            except Exception:
                pass

    async def probe_capabilities(self) -> ProbeReport:
        """Auto-probe text connectivity & multimodal vision support at startup or on demand."""
        client = self.client
        model = self.model
        if not self.is_configured or client is None:
            self.text_ready = False
            self.vision_supported = False
            if self.config_warning:
                self.vision_note = self.config_warning
                return ProbeReport(
                    text_ok=False,
                    vision_supported=False,
                    text_detail=self.config_warning,
                    vision_detail=self.config_warning,
                )
            self.vision_note = "未配置 AI_API_KEY，当前以「纯本地基础防护模式」运行（可在私聊 /start 点按钮配置）"
            return ProbeReport(
                text_ok=False,
                vision_supported=False,
                text_detail="未配置 AI_API_KEY，已启用纯本地基础防护引擎",
                vision_detail=self.vision_note,
            )

        text_ok = False
        text_detail = ""
        try:
            resp = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": "Reply with OK"}],
                timeout=self.timeout,
            )
            content = (resp.choices[0].message.content or "").strip() if resp.choices else ""
            text_ok = True
            text_detail = f"连接正常（响应: {content[:30] or 'OK'}）"
        except Exception as exc:
            text_ok = False
            text_detail = f"文本模型测试失败: {format_safe_llm_error(exc)}"

        self.text_ready = text_ok

        vision_ok = False
        vision_detail = ""
        if not text_ok:
            vision_detail = "跳过识图探测（文本接口未连通）"
        else:
            probe_img = _make_probe_jpeg_data_url()
            try:
                await client.chat.completions.create(
                    model=model,
                    messages=[
                        {
                            "role": "user",
                            "content": [
                                {"type": "text", "text": "Reply with OK if you can see this image."},
                                {"type": "image_url", "image_url": {"url": probe_img}},
                            ],
                        }
                    ],
                    timeout=self.timeout,
                )
                vision_ok = True
                vision_detail = f"模型 {model} 支持多模态识图，图片/贴纸/二维码广告检测已自动开启"
            except Exception as exc:
                vision_ok = False
                err_short = format_safe_llm_error(exc)
                vision_detail = (
                    f"模型 {model} 不支持图片识别（{err_short}），"
                    "已自动降级为纯文本+隐形链接+编辑+防刷屏模式正常运行"
                )

        # Only write back probe results if config wasn't replaced concurrently
        if self.client is client and self.model == model:
            self.vision_supported = vision_ok
            self.vision_note = vision_detail
        return ProbeReport(
            text_ok=text_ok,
            vision_supported=vision_ok,
            text_detail=text_detail,
            vision_detail=vision_detail,
        )

    async def classify(
        self,
        *,
        summary_text: str,
        group_topic: str = "",
        image_data_url: Optional[str] = None,
        allow_vision: bool = True,
    ) -> SpamVerdict:
        # Keep system prompt 100% static to maximize Prefix KV Cache hit rate across all groups.
        full_user_text = summary_text
        if group_topic.strip():
            full_user_text = f"【本群主题】: {group_topic.strip()}\n{summary_text}"

        use_vision = bool(image_data_url and allow_vision and self.vision_supported)

        if use_vision:
            user_content: Any = [
                {"type": "text", "text": full_user_text},
                {"type": "image_url", "image_url": {"url": image_data_url}},
            ]
        else:
            user_content = full_user_text

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_content},
        ]

        async with self.sem:
            try:
                raw, usage_tuple = await self._call_with_retry(messages)
            except Exception as exc:
                if use_vision:
                    logger.warning(
                        "多模态识图调用失败（%s），自动降级为纯文本审核本次消息",
                        format_safe_llm_error(exc),
                    )
                    use_vision = False
                    fallback_messages = [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": full_user_text},
                    ]
                    raw, usage_tuple = await self._call_with_retry(fallback_messages)
                else:
                    raise

        is_spam, score, reason = parse_verdict_json(raw)
        p_tok, c_tok, hit_tok = usage_tuple
        return SpamVerdict(
            is_spam=is_spam,
            score=score,
            reason=reason,
            used_vision=use_vision,
            prompt_tokens=p_tok,
            completion_tokens=c_tok,
            cached_tokens=hit_tok,
        )

    async def _call_with_retry(
        self, messages: list[dict[str, Any]], retries: int = 1
    ) -> tuple[str, tuple[int, int, int]]:
        client = self.client
        model = self.model
        if client is None or not model:
            raise RuntimeError("AI 客户端当前未配置")
        last_err: Optional[Exception] = None
        for attempt in range(retries + 1):
            try:
                resp = await client.chat.completions.create(
                    model=model,
                    messages=messages,
                    timeout=self.timeout,
                )
                content = (resp.choices[0].message.content or "") if resp.choices else ""
                return content, _extract_usage(resp)
            except Exception as exc:
                last_err = exc
                if attempt < retries:
                    await asyncio.sleep(0.5 * (attempt + 1))
        assert last_err is not None
        raise last_err
