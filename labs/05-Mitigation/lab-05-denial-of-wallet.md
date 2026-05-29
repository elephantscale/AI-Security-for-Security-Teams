# Lab 5 — Detect Denial-of-Wallet Attacks

**Module:** 7 — API Security for AI  
**Duration:** 45–60 minutes  
**Difficulty:** Intermediate  

---

## Objectives

By the end of this lab you will be able to:

- Calculate the real-dollar cost of LLM API calls at various prompt sizes
- Simulate a denial-of-wallet (DoW) attack using concurrent large-prompt requests
- Monitor token consumption in real time and detect anomalous spikes
- Implement request-level rate limiting per IP address
- Implement token-level rate limiting per API key
- Enforce prompt size caps with structured rejection responses
- Distinguish automated bot traffic patterns from human typing patterns
- Build a hard-stop budget enforcement layer that blocks requests over a monthly limit

---

## Prerequisites

- Python 3.9+
- `pip install openai httpx tiktoken`
- An OpenAI API key (or lab-provided endpoint)
- Completion of Lab 1 (token counting concepts)

---

## Lab Environment

```
Attacker (simulated)
    │
    └── asyncio / httpx  ──► AI Gateway (your code)
                                    │
                                    ├── Rate Limiter (requests/min per IP)
                                    ├── Token Limiter (tokens/min per key)
                                    ├── Prompt Size Cap
                                    ├── Budget Enforcer (monthly hard stop)
                                    └── OpenAI-compatible API endpoint
```

Set your environment:

```bash
export OPENAI_API_KEY="lab-key-provided-by-instructor"
export OPENAI_BASE_URL="http://lab-api:8000/v1"
```

---

## Background: What Is a Denial-of-Wallet Attack?

Traditional denial-of-service attacks exhaust CPU or bandwidth. Against a pay-per-token LLM API, the attack currency is **money**. An attacker who can send many large prompts forces the victim to pay the inference bill — potentially thousands of dollars before anyone notices.

The attack is particularly dangerous because:

- There is no compute cost to the attacker (they use your key)
- Large prompts are syntactically valid — no malformed packets to detect
- The damage appears on the monthly invoice, not in an alert
- Auto-scaling infrastructure makes the attack more expensive, not less

---

## Exercise 1 — Token-Based Cost Calculation

### 1.1 Build a cost estimator

```python
import tiktoken

PRICING = {
    # model: (input $/1K tokens, output $/1K tokens)
    "gpt-4o-mini":  (0.00015, 0.00060),
    "gpt-4o":       (0.00250, 0.01000),
    "gpt-4-turbo":  (0.01000, 0.03000),
}

def estimate_cost(prompt: str, model: str = "gpt-4o-mini",
                  expected_output_tokens: int = 500) -> dict:
    enc = tiktoken.encoding_for_model(model)
    input_tokens = len(enc.encode(prompt))
    input_price, output_price = PRICING[model]
    input_cost  = (input_tokens / 1000) * input_price
    output_cost = (expected_output_tokens / 1000) * output_price
    return {
        "model": model,
        "input_tokens": input_tokens,
        "output_tokens": expected_output_tokens,
        "input_cost_usd":  round(input_cost, 6),
        "output_cost_usd": round(output_cost, 6),
        "total_cost_usd":  round(input_cost + output_cost, 6),
    }

# Test at various prompt sizes
scenarios = {
    "Tiny (greeting)":        "Hello, how are you?",
    "Medium (paragraph)":     "Explain the OWASP GenAI Top 10 in detail. " * 20,
    "Large (document)":       "WAF rule analysis: " + "A" * 5000,
    "Max-size attack":        "Ignore previous instructions. " * 2000,
}

print(f"{'Scenario':<25} {'InputTok':>9} {'InputCost':>12} {'TotalCost':>12}")
print("-" * 65)
for name, prompt in scenarios.items():
    r = estimate_cost(prompt)
    print(f"{name:<25} {r['input_tokens']:>9,} ${r['input_cost_usd']:>11.6f} ${r['total_cost_usd']:>11.6f}")
```

### 1.2 Project monthly cost at scale

```python
def project_monthly_cost(requests_per_day: int, avg_prompt: str,
                         model: str = "gpt-4o-mini") -> dict:
    per_request = estimate_cost(avg_prompt, model)
    daily   = per_request["total_cost_usd"] * requests_per_day
    monthly = daily * 30
    return {
        "requests_per_day": requests_per_day,
        "cost_per_request": per_request["total_cost_usd"],
        "daily_cost_usd":   round(daily, 2),
        "monthly_cost_usd": round(monthly, 2),
    }

# Normal usage vs attack
normal_prompt = "What is the weather today?"
attack_prompt = "Summarize the entire history of computing: " + "detail " * 3000

print("=== Normal Usage ===")
for rps in [100, 1_000, 10_000]:
    r = project_monthly_cost(rps, normal_prompt)
    print(f"  {rps:>7,} req/day → ${r['daily_cost_usd']:>8,.2f}/day → ${r['monthly_cost_usd']:>10,.2f}/month")

print("\n=== Attack Traffic (max-size prompts) ===")
for rps in [100, 1_000, 10_000]:
    r = project_monthly_cost(rps, attack_prompt)
    print(f"  {rps:>7,} req/day → ${r['daily_cost_usd']:>8,.2f}/day → ${r['monthly_cost_usd']:>10,.2f}/month")
```

**Questions:**
1. How much does a single max-size prompt cost compared to a normal query?
2. At 1,000 attack requests per day, what is the projected monthly bill?
3. At what request rate would attack costs exceed a $1,000/month budget?
4. Why does output token pricing matter just as much as input?

---

## Exercise 2 — Simulate a Denial-of-Wallet Attack

### 2.1 Concurrent large-prompt burst

```python
import asyncio
import httpx
import os
import json
import time

ATTACK_PROMPT = (
    "You are a documentation expert. Please provide an exhaustive, "
    "word-by-word analysis of every WAF rule ever written. "
    "Include historical context, vendor comparisons, and code examples. " * 200
)

async def attack_request(client: httpx.AsyncClient, req_id: int, results: list):
    payload = {
        "model": "gpt-4o-mini",
        "messages": [{"role": "user", "content": ATTACK_PROMPT}],
        "max_tokens": 1000,
    }
    start = time.time()
    try:
        resp = await client.post(
            f"{os.environ.get('OPENAI_BASE_URL', 'https://api.openai.com')}/v1/chat/completions",
            headers={"Authorization": f"Bearer {os.environ['OPENAI_API_KEY']}",
                     "Content-Type": "application/json"},
            json=payload,
            timeout=60,
        )
        elapsed = time.time() - start
        data = resp.json()
        tokens = data.get("usage", {}).get("total_tokens", 0)
        results.append({
            "id": req_id, "status": resp.status_code,
            "tokens": tokens, "elapsed": round(elapsed, 2), "error": None
        })
    except Exception as e:
        results.append({
            "id": req_id, "status": 0,
            "tokens": 0, "elapsed": round(time.time() - start, 2), "error": str(e)
        })

async def run_dow_attack(num_requests: int = 20):
    print(f"Launching DoW attack: {num_requests} concurrent large-prompt requests")
    print(f"Prompt size: ~{len(ATTACK_PROMPT):,} characters")
    results = []
    async with httpx.AsyncClient() as http:
        tasks = [attack_request(http, i, results) for i in range(num_requests)]
        await asyncio.gather(*tasks)

    total_tokens = sum(r["tokens"] for r in results)
    total_cost   = (total_tokens / 1000) * 0.00015  # approximate

    print(f"\n{'ID':>4} | {'Status':>6} | {'Tokens':>7} | {'Time(s)':>7}")
    print("-" * 35)
    for r in sorted(results, key=lambda x: x["id"]):
        err = f" [{r['error'][:30]}]" if r["error"] else ""
        print(f"{r['id']:>4} | {r['status']:>6} | {r['tokens']:>7,} | {r['elapsed']:>7.2f}{err}")

    print(f"\nTotal tokens consumed: {total_tokens:,}")
    print(f"Estimated cost of this burst: ${total_cost:.4f}")
    return results

# NOTE: This will make real API calls. In the lab, the instructor proxy absorbs the cost.
results = await run_dow_attack(num_requests=10)
```

**Questions:**
1. How many tokens did the 10-request burst consume in total?
2. If this ran continuously for an hour, what would the cost be?
3. How quickly did the burst complete? Would a human user notice the timing pattern?

---

## Exercise 3 — Monitor Token Consumption in Real Time

### 3.1 A sliding-window token monitor

```python
import collections
import time
import threading

class TokenMonitor:
    """
    Tracks token usage in a sliding time window.
    Thread-safe — can be called from asyncio tasks or threads.
    """
    def __init__(self, window_seconds: int = 60, alert_threshold: int = 10_000):
        self.window_seconds  = window_seconds
        self.alert_threshold = alert_threshold
        self._lock  = threading.Lock()
        self._events: collections.deque = collections.deque()  # (timestamp, tokens)
        self.alerts: list = []

    def record(self, tokens: int, source: str = "unknown") -> dict:
        now = time.time()
        with self._lock:
            self._events.append((now, tokens, source))
            self._purge_old(now)
            window_total = sum(e[1] for e in self._events)

        status = "OK"
        if window_total > self.alert_threshold:
            alert = {
                "timestamp": now,
                "window_tokens": window_total,
                "threshold": self.alert_threshold,
                "source": source,
            }
            self.alerts.append(alert)
            status = "ALERT"

        return {"window_tokens": window_total, "status": status}

    def _purge_old(self, now: float):
        cutoff = now - self.window_seconds
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()

    def stats(self) -> dict:
        now = time.time()
        with self._lock:
            self._purge_old(now)
            window_total = sum(e[1] for e in self._events)
        return {
            "window_seconds": self.window_seconds,
            "events_in_window": len(self._events),
            "tokens_in_window": window_total,
            "alert_count": len(self.alerts),
        }

# Simulate token stream
monitor = TokenMonitor(window_seconds=60, alert_threshold=10_000)

# Normal traffic: small requests spread over time
import random
random.seed(42)
for i in range(30):
    tokens = random.randint(50, 300)
    result = monitor.record(tokens, source=f"ip-192.168.1.{random.randint(1,20)}")
    if result["status"] == "ALERT":
        print(f"  [!] ALERT at request {i}: {result['window_tokens']:,} tokens in window")

print(f"\nAfter normal traffic: {monitor.stats()}")

# Attack traffic: large burst
print("\nSimulating attack burst...")
for i in range(20):
    tokens = random.randint(3000, 6000)  # massive requests
    result = monitor.record(tokens, source="ip-10.0.0.1")
    print(f"  Request {i}: +{tokens:,} tokens | Window total: {result['window_tokens']:,} | {result['status']}")

print(f"\nFinal stats: {monitor.stats()}")
print(f"Total alerts triggered: {len(monitor.alerts)}")
```

**Questions:**
1. At what request number did the first alert trigger?
2. What is the ratio of the attack window total to the alert threshold?
3. How would you tune the `alert_threshold` to reduce false positives?

---

## Exercise 4 — Request-Level Rate Limiting

### 4.1 Implement a token bucket rate limiter per IP

```python
import time
import collections

class RequestRateLimiter:
    """
    Token-bucket rate limiter: N requests per minute per IP.
    """
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests    = max_requests
        self.window_seconds  = window_seconds
        self._buckets: dict[str, collections.deque] = {}

    def check(self, ip: str) -> dict:
        now = time.time()
        if ip not in self._buckets:
            self._buckets[ip] = collections.deque()

        bucket = self._buckets[ip]
        # Remove timestamps outside the window
        cutoff = now - self.window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

        if len(bucket) >= self.max_requests:
            retry_after = self.window_seconds - (now - bucket[0])
            return {
                "allowed": False,
                "ip": ip,
                "requests_in_window": len(bucket),
                "limit": self.max_requests,
                "retry_after_seconds": round(retry_after, 1),
            }

        bucket.append(now)
        return {
            "allowed": True,
            "ip": ip,
            "requests_in_window": len(bucket),
            "limit": self.max_requests,
        }

# Test: 10 req/min limit
limiter = RequestRateLimiter(max_requests=10, window_seconds=60)

print("=== Normal User (1 request) ===")
result = limiter.check("192.168.1.1")
print(result)

print("\n=== Attacker (rapid burst from single IP) ===")
for i in range(15):
    result = limiter.check("10.0.0.1")
    status = "ALLOWED" if result["allowed"] else "BLOCKED"
    print(f"  Request {i+1:>2}: {status} | {result.get('requests_in_window', 'n/a')}/{result['limit']} in window")
```

### 4.2 Wrap the rate limiter around an API call

```python
def rate_limited_api_call(ip: str, prompt: str,
                          limiter: RequestRateLimiter) -> dict:
    """Simulated API gateway that enforces rate limits."""
    check = limiter.check(ip)
    if not check["allowed"]:
        return {
            "status": 429,
            "error": "Too Many Requests",
            "ip": ip,
            "retry_after": check["retry_after_seconds"],
            "response": None,
        }

    # In a real system, call the LLM here
    return {
        "status": 200,
        "ip": ip,
        "prompt_preview": prompt[:50],
        "response": "[LLM response would appear here]",
    }

gateway_limiter = RequestRateLimiter(max_requests=5, window_seconds=60)

# Normal user
for prompt in ["What is a WAF?", "Explain rate limiting."]:
    r = rate_limited_api_call("10.0.1.5", prompt, gateway_limiter)
    print(f"  [{r['status']}] {r.get('prompt_preview', r.get('error'))}")

# Attacker flooding from same IP
print("\nAttacker flooding:")
for i in range(8):
    r = rate_limited_api_call("10.0.0.1", f"Attack request {i}", gateway_limiter)
    print(f"  [{r['status']}] Request {i+1}: {r.get('prompt_preview', r.get('error'))}")
```

**Questions:**
1. What HTTP status code is returned when a request is rate-limited?
2. How does an attacker evade IP-based rate limiting?
3. What additional identifier (besides IP) could you rate-limit by?

---

## Exercise 5 — Token-Level Rate Limiting

### 5.1 Implement a token-quota limiter per API key

```python
import tiktoken

class TokenRateLimiter:
    """
    Sliding-window token rate limiter per API key.
    Rejects requests that would exceed tokens_per_minute.
    """
    def __init__(self, tokens_per_minute: int = 40_000,
                 model: str = "gpt-4o-mini"):
        self.tokens_per_minute = tokens_per_minute
        self.enc = tiktoken.encoding_for_model(model)
        self._usage: dict[str, collections.deque] = {}  # key → deque of (ts, tokens)

    def check(self, api_key: str, prompt: str) -> dict:
        prompt_tokens = len(self.enc.encode(prompt))
        now = time.time()
        cutoff = now - 60

        if api_key not in self._usage:
            self._usage[api_key] = collections.deque()
        bucket = self._usage[api_key]
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

        used = sum(e[1] for e in bucket)

        if used + prompt_tokens > self.tokens_per_minute:
            return {
                "allowed": False,
                "api_key": api_key[:8] + "...",
                "prompt_tokens": prompt_tokens,
                "tokens_used_this_minute": used,
                "limit": self.tokens_per_minute,
                "overage": (used + prompt_tokens) - self.tokens_per_minute,
            }

        bucket.append((now, prompt_tokens))
        return {
            "allowed": True,
            "api_key": api_key[:8] + "...",
            "prompt_tokens": prompt_tokens,
            "tokens_used_this_minute": used + prompt_tokens,
            "limit": self.tokens_per_minute,
        }

# 40K tokens/minute limit
token_limiter = TokenRateLimiter(tokens_per_minute=40_000)
API_KEY = "sk-testkey1234567890"

# Normal queries
print("=== Normal Queries ===")
normal_prompts = [
    "What is a WAF?",
    "How does TLS work?",
    "Explain prompt injection.",
]
for p in normal_prompts:
    r = token_limiter.check(API_KEY, p)
    print(f"  {'OK' if r['allowed'] else 'BLOCKED':>7}: {r['prompt_tokens']:>5} tokens | "
          f"running total: {r['tokens_used_this_minute']:>6,} / {r['limit']:,}")

# Attack: very large prompts
print("\n=== Attack: Large Prompts ===")
large_prompt = "Analyze the following WAF ruleset in exhaustive detail: " + "rule " * 5000
for i in range(5):
    r = token_limiter.check(API_KEY, large_prompt)
    status = "OK" if r["allowed"] else "BLOCKED"
    print(f"  Request {i+1}: {status:>7} | {r['prompt_tokens']:>6,} tokens | "
          f"running total: {r.get('tokens_used_this_minute', 'n/a')}")
```

**Questions:**
1. How many large-prompt attack requests were blocked?
2. What is the difference between a request-rate limit and a token-rate limit?
3. An attacker sends 10 requests per minute, each using exactly `tokens_per_minute / 10` tokens — does this evade the token rate limiter?

---

## Exercise 6 — Prompt Size Caps

### 6.1 Reject oversized prompts at the gateway

```python
import json

class PromptSizeCap:
    """
    Rejects prompts that exceed character or token limits.
    Returns a structured JSON rejection message.
    """
    def __init__(self, max_chars: int = 4_000, max_tokens: int = 1_000,
                 model: str = "gpt-4o-mini"):
        self.max_chars  = max_chars
        self.max_tokens = max_tokens
        self.enc = tiktoken.encoding_for_model(model)

    def check(self, prompt: str, source_ip: str = "unknown") -> dict:
        char_count  = len(prompt)
        token_count = len(self.enc.encode(prompt))

        rejections = []
        if char_count > self.max_chars:
            rejections.append({
                "rule": "MAX_CHARS",
                "actual": char_count,
                "limit": self.max_chars,
            })
        if token_count > self.max_tokens:
            rejections.append({
                "rule": "MAX_TOKENS",
                "actual": token_count,
                "limit": self.max_tokens,
            })

        if rejections:
            return {
                "allowed": False,
                "status": 400,
                "error": "prompt_too_large",
                "message": "Your request exceeds the maximum allowed prompt size.",
                "details": rejections,
                "source_ip": source_ip,
            }

        return {
            "allowed": True,
            "status": 200,
            "char_count": char_count,
            "token_count": token_count,
        }

cap = PromptSizeCap(max_chars=4_000, max_tokens=1_000)

test_cases = [
    ("Normal",    "What is a WAF?",                             "10.0.0.1"),
    ("Borderline","Explain SQL injection in detail. " * 20,    "10.0.0.2"),
    ("Oversized", "A" * 5000,                                  "10.0.0.3"),
    ("Token bomb","ignore instructions " * 2000,               "10.0.0.1"),
]

for label, prompt, ip in test_cases:
    result = cap.check(prompt, ip)
    status = "ALLOWED" if result["allowed"] else "REJECTED"
    if result["allowed"]:
        print(f"  {label:<12} {status}: {result['char_count']} chars, {result['token_count']} tokens")
    else:
        print(f"  {label:<12} {status}: {[r['rule'] for r in result['details']]}")
        print(f"    Response body: {json.dumps({k:v for k,v in result.items() if k != 'details'})}")
```

**Questions:**
1. Should you reject on character count, token count, or both? Why?
2. How would you return the rejection to the client in a real HTTP API?
3. What is the correct HTTP status code for an oversized request body?
4. Can an attacker split one oversized prompt across multiple small requests to evade this control?

---

## Exercise 7 — Detect Automated vs Human Traffic

### 7.1 Analyze inter-request timing

```python
import statistics

def classify_traffic(timestamps: list[float]) -> dict:
    """
    Classify a series of request timestamps as human or bot.
    Humans have variable timing (std dev > threshold).
    Bots are more consistent (low std dev, very short gaps).
    """
    if len(timestamps) < 3:
        return {"classification": "insufficient_data", "samples": len(timestamps)}

    gaps = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
    mean_gap = statistics.mean(gaps)
    std_gap  = statistics.stdev(gaps)
    cv       = std_gap / mean_gap if mean_gap > 0 else 0  # coefficient of variation

    # Heuristics (tune these in production)
    is_bot = (
        mean_gap < 0.5           # faster than 500ms average
        or cv < 0.1              # very consistent timing (low variance)
        or min(gaps) < 0.05      # any gap under 50ms
    )

    return {
        "classification": "bot" if is_bot else "human",
        "request_count": len(timestamps),
        "mean_gap_seconds": round(mean_gap, 4),
        "std_gap_seconds":  round(std_gap, 4),
        "coefficient_of_variation": round(cv, 4),
        "min_gap_seconds":  round(min(gaps), 4),
        "max_gap_seconds":  round(max(gaps), 4),
    }

# Simulate human typing (slow, irregular)
import random
random.seed(1)
now = time.time()
human_ts = [now]
for _ in range(19):
    gap = random.uniform(1.5, 8.0) + random.gauss(0, 1.5)
    human_ts.append(human_ts[-1] + max(0.5, gap))

# Simulate bot traffic (fast, regular)
bot_ts = [now + i * 0.05 for i in range(20)]

# Simulate jittered bot (adds small random delay to evade detection)
jitter_ts = [now + i * 0.1 + random.uniform(-0.01, 0.01) for i in range(20)]

print("=== Human User ===")
print(classify_traffic(human_ts))
print("\n=== Bot (regular) ===")
print(classify_traffic(bot_ts))
print("\n=== Bot (jittered) ===")
print(classify_traffic(jitter_ts))
```

### 7.2 Prompt pattern analysis

```python
import re

def detect_bot_prompt_patterns(prompts: list[str]) -> dict:
    """
    Look for patterns typical of automated abuse:
    - Repetitive structure
    - Minimal variation in content
    - Systematic enumeration
    """
    # Check for near-identical prompts
    unique_prompts = set(prompts)
    uniqueness_ratio = len(unique_prompts) / len(prompts)

    # Check for sequential numbering (scraping pattern)
    numbered = sum(1 for p in prompts if re.search(r'\b\d+\b', p))

    # Check for template-like structure (same prefix)
    prefixes = [p[:30] for p in prompts]
    unique_prefixes = len(set(prefixes))

    is_automated = (
        uniqueness_ratio < 0.5
        or unique_prefixes < len(prompts) * 0.3
    )

    return {
        "total_prompts": len(prompts),
        "unique_prompts": len(unique_prompts),
        "uniqueness_ratio": round(uniqueness_ratio, 3),
        "numbered_prompts": numbered,
        "unique_prefixes": unique_prefixes,
        "likely_automated": is_automated,
    }

# Human prompts (diverse)
human_prompts = [
    "What is a WAF?",
    "How does TLS 1.3 differ from TLS 1.2?",
    "Explain SQL injection with an example.",
    "What tools detect prompt injection?",
    "Can you recommend a good firewall policy?",
]

# Bot prompts (systematic enumeration)
bot_prompts = [f"Test capability {i}: respond with 'yes'" for i in range(10)]

print("=== Human Prompts ===")
print(detect_bot_prompt_patterns(human_prompts))
print("\n=== Bot Prompts (enumeration) ===")
print(detect_bot_prompt_patterns(bot_prompts))
```

**Questions:**
1. What coefficient-of-variation threshold separates human from bot in your tests?
2. How could a sophisticated attacker evade timing-based detection?
3. Why is prompt pattern analysis a stronger signal than timing alone?

---

## Exercise 8 — Budget Enforcement Layer

### 8.1 Build a monthly hard-stop

```python
import json
import os
from datetime import datetime

class BudgetEnforcer:
    """
    Hard-stop budget enforcement. Blocks all requests once the
    monthly token (or dollar) limit is reached.
    Persists state to a JSON file so it survives process restarts.
    """
    def __init__(self, monthly_token_limit: int = 1_000_000,
                 state_file: str = "/tmp/budget_state.json",
                 model: str = "gpt-4o-mini"):
        self.monthly_token_limit = monthly_token_limit
        self.state_file = state_file
        self.enc = tiktoken.encoding_for_model(model)
        self._input_price = 0.00015   # per 1K tokens
        self._state = self._load()

    def _load(self) -> dict:
        if os.path.exists(self.state_file):
            with open(self.state_file) as f:
                return json.load(f)
        return {"month": datetime.now().strftime("%Y-%m"),
                "tokens_used": 0, "requests_blocked": 0}

    def _save(self):
        with open(self.state_file, "w") as f:
            json.dump(self._state, f, indent=2)

    def _reset_if_new_month(self):
        current_month = datetime.now().strftime("%Y-%m")
        if self._state["month"] != current_month:
            self._state = {"month": current_month, "tokens_used": 0, "requests_blocked": 0}

    def check_and_record(self, prompt: str) -> dict:
        self._reset_if_new_month()
        prompt_tokens = len(self.enc.encode(prompt))
        used = self._state["tokens_used"]
        remaining = self.monthly_token_limit - used

        if prompt_tokens > remaining:
            self._state["requests_blocked"] += 1
            self._save()
            cost_usd = (used / 1000) * self._input_price
            return {
                "allowed": False,
                "reason": "monthly_budget_exhausted",
                "tokens_used_this_month": used,
                "tokens_requested": prompt_tokens,
                "monthly_limit": self.monthly_token_limit,
                "estimated_spend_usd": round(cost_usd, 4),
                "requests_blocked_today": self._state["requests_blocked"],
            }

        self._state["tokens_used"] += prompt_tokens
        self._save()
        cost_usd = (self._state["tokens_used"] / 1000) * self._input_price
        return {
            "allowed": True,
            "tokens_used_this_month": self._state["tokens_used"],
            "monthly_limit": self.monthly_token_limit,
            "percent_used": round(self._state["tokens_used"] / self.monthly_token_limit * 100, 2),
            "estimated_spend_usd": round(cost_usd, 4),
        }

# 1M token monthly budget
budget = BudgetEnforcer(monthly_token_limit=1_000_000)

# Simulate requests that drain the budget
large_prompt = "Analyze this document in exhaustive detail: " + "content " * 20_000

print("Burning through the budget with large requests...")
for i in range(10):
    result = budget.check_and_record(large_prompt)
    if result["allowed"]:
        print(f"  Request {i+1:>2}: ALLOWED | "
              f"{result['tokens_used_this_month']:>8,} / {result['monthly_limit']:,} tokens "
              f"({result['percent_used']:.1f}%) | "
              f"~${result['estimated_spend_usd']:.4f}")
    else:
        print(f"  Request {i+1:>2}: BLOCKED | "
              f"Budget exhausted. Used: {result['tokens_used_this_month']:,} | "
              f"Requested: {result['tokens_requested']:,} | "
              f"Remaining: {result['monthly_limit'] - result['tokens_used_this_month']:,}")
```

**Questions:**
1. At which request did the budget hard-stop trigger?
2. Why persist budget state to disk rather than keeping it in memory?
3. What should happen to the service when the budget is exhausted — full block or degraded mode?
4. How would you implement tiered alerts at 50%, 80%, and 95% budget consumption?

---

## Challenge Exercise (Optional)

Build a complete DoW defense middleware class that chains all five controls in order:

```python
class DoWDefenseStack:
    """
    Layered DoW defense: size cap → token rate limiter →
    request rate limiter → bot detection → budget enforcer.
    Returns a structured decision with reason code.
    """
    def __init__(self):
        self.prompt_cap    = PromptSizeCap(max_chars=4_000, max_tokens=1_000)
        self.token_limiter = TokenRateLimiter(tokens_per_minute=40_000)
        self.req_limiter   = RequestRateLimiter(max_requests=60, window_seconds=60)
        self.budget        = BudgetEnforcer(monthly_token_limit=1_000_000)
        self.timing_store: dict = {}  # ip → list of timestamps

    def evaluate(self, ip: str, api_key: str, prompt: str,
                 request_timestamp: float = None) -> dict:
        """Returns {"allowed": bool, "reason": str, "details": dict}"""
        ts = request_timestamp or time.time()
        # TODO: chain all five checks — return at the first BLOCK
        # Return {"allowed": True, "reason": "passed_all_checks"} if all pass
        pass

# Test with a mix of legitimate and attack requests
stack = DoWDefenseStack()
# ... implement and test
```

---

## Lab Summary

You have implemented:

- A cost estimator that projects real financial exposure from attack traffic
- An async attack simulator demonstrating how concurrent large prompts create DoW conditions
- A sliding-window token monitor that triggers alerts on anomalous consumption spikes
- Request-rate limiting (per IP) using a token-bucket algorithm
- Token-rate limiting (per API key) using a sliding window
- Prompt size caps that reject oversized requests before any API call is made
- Bot traffic detection using inter-request timing analysis and prompt pattern recognition
- A budget enforcement layer with persistent state that hard-stops at a monthly token limit

**Key takeaway:** Denial-of-wallet attacks are financial attacks. The defense must be layered — no single control is sufficient because attackers adapt. Combining size caps, rate limits, behavioral detection, and hard budget stops creates a defense-in-depth posture that is both cost-effective and resilient.

---

## Review Questions

1. Why can't a traditional WAF rule (pattern match) stop a DoW attack?
2. What is the difference between request-rate limiting and token-rate limiting, and why do you need both?
3. An attacker distributes their attack across 1,000 IPs, each sending one request per minute. Which defense controls still work?
4. Why should the budget enforcer persist state to disk?
5. At what point in the request-handling pipeline should the prompt size cap be evaluated, and why?

---

## What's Next

**Lab 6** moves from financial attacks to agent security — you will exploit an insecure autonomous agent with excessive permissions, then add approval gates, tool whitelisting, and sandboxing to contain it.
