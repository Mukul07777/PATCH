"""Nemotron model router on Nebius Token Factory.

Three tiers, each used for the job it is good at:
  nano  -> fast, cheap triage and classification
  super -> planning and first-pass code changes
  ultra -> deep reasoning when a fix fails and we need to escalate
"""
import json
import re
import time

import httpx

from . import config

TIER_HINTS = {"nano": "nano", "super": "super", "ultra": "ultra"}


class LLMError(RuntimeError):
    pass


class Router:
    def __init__(self, emit):
        self.emit = emit
        self.models = dict(config.MODEL_OVERRIDES)
        self.usage = {t: {"calls": 0, "in": 0, "out": 0, "seconds": 0.0} for t in TIER_HINTS}
        self._client = httpx.Client(
            base_url=config.NEBIUS_BASE_URL,
            headers={"Authorization": f"Bearer {config.NEBIUS_API_KEY}"},
            timeout=300,
        )

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
            match = [i for i in nemotron if hint in i.lower()]
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

    def chat(self, tier, system, user, purpose, max_tokens=4096, temperature=0.2):
        model = self.models[tier]
        self.emit({"type": "model_call", "tier": tier, "model": model, "purpose": purpose, "status": "start"})
        t0 = time.time()
        body = {
            "model": model,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        for attempt in range(3):
            try:
                r = self._client.post("/chat/completions", json=body)
                if r.status_code >= 500 or r.status_code == 429:
                    raise httpx.HTTPStatusError("retryable", request=r.request, response=r)
                r.raise_for_status()
                break
            except (httpx.HTTPStatusError, httpx.TransportError) as e:
                if attempt == 2:
                    raise LLMError(f"{model}: {e}") from e
                time.sleep(2 * (attempt + 1))
        data = r.json()
        msg = data["choices"][0]["message"]
        text = msg.get("content") or ""
        if not text.strip():  # some reasoning models put everything in reasoning_content when the budget runs out
            text = msg.get("reasoning_content") or msg.get("reasoning") or ""
        usage = data.get("usage") or {}
        dt = time.time() - t0
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

    def chat_json(self, tier, system, user, purpose, **kw):
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


def strip_thinking(text):
    return re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()


def parse_json(text):
    text = text.strip()
    if "</think>" in text:
        text = text.split("</think>")[-1].strip()
    fence = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.S)
    if fence:
        text = fence.group(1).strip()
    try:
        return json.loads(text)
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
