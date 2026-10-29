"""Nemotron model router on Nebius Token Factory.

Three tiers, each used for the job it is good at:
  nano  -> fast, cheap triage and classification
  super -> planning and first-pass code changes
  ultra -> deep reasoning when a fix fails and we need to escalate
"""
import json
import re
import threading
import time

import httpx

from . import config

# id substrings per tier; Nebius names its Nano-class tier "Lightning", others use "mini"
TIER_HINTS = {"nano": ("nano", "lightning", "mini"), "super": ("super",), "ultra": ("ultra",)}


class LLMError(RuntimeError):
    pass


class Router:
    def __init__(self, emit):
        self.emit = emit
        self.models = dict(config.MODEL_OVERRIDES)
        self.last_reasoning = ""  # reasoning text of the most recent reply (for salvaging code from it)
        self.usage = {t: {"calls": 0, "in": 0, "out": 0, "seconds": 0.0} for t in TIER_HINTS}
        self._client = httpx.Client(
            base_url=config.NEBIUS_BASE_URL,
            headers={"Authorization": f"Bearer {config.NEBIUS_API_KEY}"},
            timeout=300,
        )
        self._lock = threading.Lock()  # usage counters are updated from worker threads
        self._unsupported = set()  # (model, feature) pairs the provider rejected; never sent again

    def discover(self):
        """Fill any tier without an explicit model from the live /models catalog."""
        if all(self.models.values()):
            return self.models
        r = self._client.get("/models")
        r.raise_for_status()
        ids = [m["id"] for m in r.json().get("data", [])]
        nemotron = [i for i in ids if "nemotron" in i.lower()]
        for tier, hint in TIER_HINTS.items():
            if self.models[tier]:
                continue
            match = [i for i in nemotron if any(h in i.lower() for h in hint)]
            # prefer instruct/non-base variants and the newest-looking id
            match.sort(key=lambda i: ("base" in i.lower(), i), reverse=False)
            if match:
                self.models[tier] = match[-1] if len(match) > 1 else match[0]
        # graceful fallback so a missing tier never blocks the pipeline
        order = ["super", "ultra", "nano"]
        for tier in TIER_HINTS:
            if not self.models[tier]:
                self.models[tier] = next((self.models[t] for t in order if self.models[t]), "")
        if not any(self.models.values()):
            raise LLMError("No Nemotron models found on Token Factory. Set MODEL_NANO/SUPER/ULTRA in .env")
        return self.models

    def _extras(self, model, reasoning, json_mode):
        """Provider-specific body fields: {feature: {field: value}} (features the provider rejected are dropped)."""
        out = {}
        style = reasoning_style()
        if reasoning in ("low", "off") and style == "openrouter":
            out["reasoning"] = {"reasoning": {"effort": "low", "exclude": True} if reasoning == "low"
                                else {"enabled": False, "exclude": True}}
        elif reasoning == "off" and style == "nim":
            out["reasoning"] = {"chat_template_kwargs": {"enable_thinking": False}}
        if json_mode:
            out["json"] = {"response_format": {"type": "json_object"}}
        return {k: v for k, v in out.items() if (model, k) not in self._unsupported}

    def chat(self, tier, system, user, purpose, max_tokens=4096, temperature=0.2, reasoning=None, timeout=None,
             json_mode=False):
        """reasoning: None (provider default) | "low" | "off". timeout: seconds; exceeding it raises LLMError."""
        model = self.models[tier]
        self.emit({"type": "model_call", "tier": tier, "model": model, "purpose": purpose, "status": "start"})
        t0 = time.time()
        base = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        extras = self._extras(model, reasoning, json_mode)
        kw = {"timeout": timeout} if timeout else {}
        attempt = 0
        while True:
            body = dict(base)
            for fields in extras.values():
                body.update(fields)
            try:
                r = self._client.post("/chat/completions", json=body, **kw)
                err = r.text.lower() if r.status_code == 400 else ""
                rejected = [k for k, f in extras.items() if any(n.lower() in err for n in _names(f) if len(n) > 4)]
                if rejected:
                    with self._lock:
                        self._unsupported.update((model, k) for k in rejected)
                    for k in rejected:
                        extras.pop(k)
                    continue  # retry without the rejected field(s); does not count as an attempt
                if r.status_code >= 500 or r.status_code == 429:
                    raise httpx.HTTPStatusError("retryable", request=r.request, response=r)
                r.raise_for_status()
                break
            except httpx.TimeoutException as e:
                if timeout:  # caller asked for a hard cap: let it escalate instead of retrying
                    raise LLMError(f"{model}: timed out after {timeout}s") from e
                if attempt == 2:
                    raise LLMError(f"{model}: {e}") from e
            except (httpx.HTTPStatusError, httpx.TransportError) as e:
                if attempt == 2:
                    raise LLMError(f"{model}: {e}") from e
            time.sleep(2 * (attempt + 1))
            attempt += 1
        data = r.json()
        msg = data["choices"][0]["message"]
        text = msg.get("content") or ""
        self.last_reasoning = msg.get("reasoning_content") or msg.get("reasoning") or ""
        if not text.strip():  # some reasoning models put everything in reasoning_content when the budget runs out
            text = msg.get("reasoning_content") or msg.get("reasoning") or ""
        usage = data.get("usage") or {}
        dt = time.time() - t0
        with self._lock:
            u = self.usage[tier]
            u["calls"] += 1
            u["in"] += usage.get("prompt_tokens", 0)
            u["out"] += usage.get("completion_tokens", 0)
            u["seconds"] += dt
        self.emit({
            "type": "model_call", "tier": tier, "model": model, "purpose": purpose, "status": "done",
            "tokens_in": usage.get("prompt_tokens", 0), "tokens_out": usage.get("completion_tokens", 0),
            "seconds": round(dt, 2),
        })
        return strip_thinking(text)

    def guard(self, kind, code):
        """One call to the NVIDIA content-safety model -> {"safe": bool, "categories": [...]}.

        Single attempt with a short timeout: any error (429, timeout, unparseable reply) raises LLMError and
        the caller falls back to the static screen.
        """
        from .guard import guard_request, parse_guard
        model = config.MODEL_GUARD
        if not model:
            raise LLMError("no guard model configured (MODEL_GUARD)")
        self.emit({"type": "model_call", "tier": "guard", "model": model, "purpose": f"Guard {kind}", "status": "start"})
        t0 = time.time()
        try:
            r = self._client.post("/chat/completions", json=guard_request(kind, code, model,
                                                                 inline_policy=reasoning_style() == "openrouter"),
                                  timeout=config.GUARD_TIMEOUT)
            r.raise_for_status()
            msg = r.json()["choices"][0]["message"]
        except Exception as e:
            raise LLMError(f"{model}: {e}") from e
        # content only: the reasoning trace quotes the output template ("User Safety: safe or unsafe ...") and
        # would parse as a verdict; empty content (token budget hit) is unparseable -> static-screen fallback
        verdict = parse_guard(msg.get("content") or "")
        self.emit({"type": "model_call", "tier": "guard", "model": model, "purpose": f"Guard {kind}",
                   "status": "done", "seconds": round(time.time() - t0, 2)})
        if verdict is None:
            raise LLMError(f"{model}: unparseable guard reply {str(msg.get('content'))[:120]!r}")
        return verdict

    def chat_json(self, tier, system, user, purpose, **kw):
        kw.setdefault("json_mode", True)
        text = self.chat(tier, system + "\nRespond with a single JSON object only. No prose.", user, purpose, **kw)
        return parse_json(text)

    def cost_report(self):
        rows, total, all_ultra = {}, 0.0, 0.0
        priced = all(config.PRICES.values())
        for tier, u in self.usage.items():
            row = dict(u, model=self.models.get(tier, ""))
            if priced:
                pin, pout = config.PRICES[tier]
                row["cost"] = (u["in"] * pin + u["out"] * pout) / 1e6
                total += row["cost"]
                uin, uout = config.PRICES["ultra"]
                all_ultra += (u["in"] * uin + u["out"] * uout) / 1e6
            rows[tier] = row
        return {"tiers": rows, "priced": priced, "total": total, "all_ultra": all_ultra}


def reasoning_style(base_url=None):
    """How this host takes a reasoning switch: "openrouter", "nim" (vLLM chat_template_kwargs) or None."""
    host = (base_url or config.NEBIUS_BASE_URL).split("//")[-1].split("/")[0]
    if host == "openrouter.ai":
        return "openrouter"
    # Nebius Token Factory serves Nemotron via vLLM and honours chat_template_kwargs (verified 2026-10-29)
    if host in ("integrate.api.nvidia.com", "api.tokenfactory.nebius.com") or "vllm" in host or host.startswith(("localhost", "127.0.0.1")):
        return "nim"
    return None


def _names(fields):
    """Every key name in a nested body fragment (to match against a 400 error message)."""
    for k, v in fields.items():
        yield k
        if isinstance(v, dict):
            yield from _names(v)


def strip_thinking(text):
    return re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()


def parse_json(text):
    text = text.strip()
    if "</think>" in text:
        text = text.split("</think>")[-1].strip()
    # whole reply, then a reply wrapped in one outer fence (greedy, so a ``` inside a JSON string such as a quoted
    # shell snippet from research does not cut it short), then each fenced block on its own
    candidates = [text]
    outer = re.fullmatch(r"```[A-Za-z0-9_-]*\s*(.*)```", text, flags=re.S)
    if outer:
        candidates.append(outer.group(1).strip())
    candidates += [m.group(1).strip() for m in re.finditer(r"```[A-Za-z0-9_-]*\s*(.*?)```", text, flags=re.S)]
    for c in candidates:
        try:
            return json.loads(c)
        except json.JSONDecodeError:
            pass
    # first complete JSON object in the text, ignoring any prose or a second object after it
    dec = json.JSONDecoder()
    for i, ch in enumerate(text):
        if ch == "{":
            try:
                return dec.raw_decode(text, i)[0]
            except json.JSONDecodeError:
                continue
    raise LLMError("Model did not return valid JSON: " + text[:300])
