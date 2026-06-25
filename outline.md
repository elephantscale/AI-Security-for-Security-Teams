# Practical AI Security for Defenders
*From prompt injection to layered runtime defense — for AppSec, SOC, infra, and WAF teams.*

© Elephant Scale

June 16, 2026

## Course Description

This course teaches security professionals how to secure modern AI-powered applications, APIs, copilots, and autonomous agents.

Students learn how traditional web attacks evolve in AI systems, how prompt injection differs from SQL injection, how AI agents abuse tools and APIs, and how runtime AI controls — WAFs, API/AI gateways, and guardrails — fit together.

Throughout, we use a recurring lens: **what can a network/proxy layer (like a WAF) actually see, and where does that visibility disappear?** It's the fastest way for any defender to reason about where AI threats are syntactic vs. semantic — and why no single layer is enough.

The course combines:
- OWASP GenAI Top 10
- Agentic AI threats
- API security
- LLM gateway architectures
- AI traffic inspection
- Runtime defense
- Practical detection engineering

The emphasis is operational:
“How do you actually defend AI systems in production?”

---

# Why This Course Matters

Most defenders today reason about:
- XSS
- SQL injection
- CSRF
- API abuse
- rate limiting

Securing AI systems adds a new threat list:
- prompt injection
- jailbreaks
- agent tool abuse
- RAG poisoning
- context-window attacks
- indirect prompt injection
- model extraction
- excessive autonomy
- LLM denial-of-wallet attacks
- AI-generated bot traffic
- AI supply chain abuse

The biggest mindset shift:
AI attacks are often semantic, not merely syntactic — which is exactly why a control that inspects bytes (a WAF) sees the request but not the intent. We keep returning to that gap to show where each defensive layer earns its place.

---

# Audience

- Security engineers & AppSec
- SOC analysts & detection engineers
- API security engineers
- Cloud / API / platform security
- DevSecOps engineers
- Security architects
- WAF / network security specialists
- AI platform engineers

---

# Skill Level

Intermediate to advanced.

Students should already understand:
- HTTP/API security
- proxies/reverse proxies
- authentication
- OWASP Top 10
- REST APIs
- basic cloud networking

---

# Learning Outcomes

By the end of the course, students can:

- Explain how AI applications differ from normal web apps
- Detect AI-specific attack patterns
- Protect LLM APIs with layered controls (WAF, gateway, guardrails)
- Build AI-aware rate limiting
- Identify prompt injection attempts
- Secure RAG architectures
- Defend agentic AI systems
- Monitor AI abuse patterns
- Design layered AI defenses
- Compose WAFs, AI gateways, and guardrails into a defense-in-depth stack

---

# Module 1 — AI Systems for Security Engineers
*Lab: Lab 01 — `01-Introduction`*

Understanding the architecture.

Topics:
- LLMs vs normal apps
- AI inference pipelines
- Prompt flow
- RAG architecture
- embeddings/vector databases
- agentic workflows
- tool calling
- AI gateways
- copilots
- MCP and agent protocols
- where WAF visibility exists
- where WAF visibility disappears

Key insight:
Traditional WAFs often lose visibility after the prompt reaches the model.

---

# Module 2 — OWASP GenAI Top 10
*Lab: none — interactive recap/discussion*

Core AI attack categories.

Topics:
- Prompt Injection
- Insecure Output Handling
- Training Data Poisoning
- Model DoS
- Supply Chain Vulnerabilities
- Sensitive Information Disclosure
- Excessive Agency
- Vector/Embedding Weaknesses
- Misinformation
- Unbounded Consumption

Include:
- differences from classic OWASP
- mapping to defensive controls (WAF, gateway, app-layer)
- where each control helps
- where each control fails

---

# Module 3 — Prompt Injection Detection
*Lab: Lab 02 — `02-Prompt-Injection`*

The “SQL injection moment” for AI.

Topics:
- direct prompt injection
- indirect prompt injection
- hidden instructions
- document-based attacks
- HTML/Markdown injection
- jailbreak patterns
- context override attacks
- role confusion attacks

Detection strategies:
- keyword heuristics
- semantic classification
- prompt linting
- instruction boundary enforcement
- allow/deny policies
- AI-aware regex patterns

Hands-on labs:
- attack a chatbot
- bypass naïve filters
- build layered detection

---

# Module 4 — AI-Aware WAF Rules
*Lab: Lab 03 — `03-WAF-Basics`*

How WAF rules evolve for AI systems.

Topics:
- protecting LLM endpoints
- inference API protection
- token-aware rate limiting
- prompt size inspection
- AI-specific signatures
- conversation anomaly detection
- multi-turn abuse patterns
- model enumeration attempts
- inference scraping
- denial-of-wallet protection

Examples:
- protecting `/v1/chat/completions`
- defending streaming APIs
- blocking recursive agent calls

---

# Module 5 — Securing RAG Pipelines
*Lab: Lab 04 — `04-RAG-Security`*

One of the biggest new attack surfaces.

Topics:
- vector DB threats
- embedding poisoning
- malicious PDFs/docs
- retrieval manipulation
- semantic poisoning
- hidden instructions in documents
- cross-document contamination
- data exfiltration via retrieval

Defenses:
- ingestion sanitization
- trust scoring
- metadata isolation
- document provenance
- retrieval policies
- segmentation

Case study:
“Upload a poisoned PDF and take over the AI assistant.”

---

# Module 6 — Agentic AI Security
*Lab: Lab 05 — `05-Agent-Security`*

Where things become dangerous.

Topics:
- excessive agency
- tool abuse
- API chaining
- autonomous loops
- permission escalation
- memory poisoning
- indirect tool execution
- agent impersonation
- credential leakage
- multi-agent attacks

Defenses:
- least privilege for agents
- approval gates
- runtime policy engines
- sandboxing
- scoped credentials
- tool whitelisting
- human-in-the-loop

This is the section managers usually care about most because the risk becomes operational and business-impacting.

---

# Module 7 — API Security for AI
*Lab: Lab 06 — `06-Denial-of-Wallet`*

AI systems are API-heavy.

Topics:
- API gateways
- GraphQL AI risks
- MCP/API abuse
- JWT protection
- AI plugin security
- agent authentication
- delegated authorization
- secret management
- signed prompts
- API inventory for AI

Tie into:
- OWASP API Security Top 10

---

# Module 8 — Detection Engineering & SOC Integration
*Lab: Lab 07 — `07-Detection`*

Operational defense.

Topics:
- AI telemetry
- prompt logging
- token analytics
- anomaly detection
- semantic SIEM pipelines
- AI attack indicators
- threat hunting for LLM abuse
- AI runtime observability

Examples:
- detecting jailbreak campaigns
- spotting automated agent abuse
- identifying model scraping

---

# Module 9 — Cloud WAFs and AI Security
*Lab: none — interactive recap/discussion*

Vendor-specific implementations.

Topics:
- AWS WAF for AI APIs
- Azure WAF
- Cloudflare AI Gateway
- API gateways
- Envoy AI filtering
- Kong AI Gateway
- NGINX AI security patterns

Comparison:
- traditional WAF vs AI gateway vs app-layer guardrail
- proxy-based vs semantic filtering

---

# Module 10 — Building a Layered AI Defense
*Lab: Lab 08 — `08-Layered-Defense`*

Important philosophical conclusion:

No single layer can secure AI (a WAF least of all, on its own).

Students build a layered model:

1. WAF
2. API gateway
3. AI gateway
4. Guardrails
5. Runtime monitoring
6. Identity/authorization
7. Sandbox
8. Human approval
9. Observability
10. Incident response

This aligns strongly with the “multi-layer security” model.

---

# Labs

The labs are what make the course compelling.

## Module ↔ Lab map

Labs run in **lab order**, which follows module order. The course has **10 modules** but **8 labs**: Modules 2 and 9 are interactive recap/discussion and have no lab. Each lab is tagged with its module throughout this outline.

| Lab | Folder | Title | Module |
|---|---|---|---|
| Lab 01 | `01-Introduction` | Explore an AI system — what's on the wire | Module 1 |
| Lab 02 | `02-Prompt-Injection` | Attack a chatbot & bypass naïve filtering | Module 3 |
| Lab 03 | `03-WAF-Basics` | Build AI-aware WAF rules | Module 4 |
| Lab 04 | `04-RAG-Security` | Poison a RAG pipeline | Module 5 |
| Lab 05 | `05-Agent-Security` | Secure an autonomous agent | Module 6 |
| Lab 06 | `06-Denial-of-Wallet` | Detect denial-of-wallet attacks | Module 7 |
| Lab 07 | `07-Detection` | Monitor AI abuse patterns in logs | Module 8 |
| Lab 08 | `08-Layered-Defense` | Build a layered AI defense architecture | Module 10 |

Modules **2** (OWASP GenAI Top 10) and **9** (Cloud WAFs) have no lab — they run as interactive recap/discussion.

---

# Capstone

Students defend a simulated enterprise AI assistant.

Attackers attempt:
- prompt injection
- tool abuse
- credential theft
- retrieval poisoning
- excessive API consumption
- agent escalation

Teams build:
- WAF rules
- AI gateway policies
- runtime detection
- guardrails
- incident response

---

# Strategic Positioning

This is NOT:
“security training with AI buzzwords.”

This IS:
“Every security team is becoming the runtime security layer for autonomous systems.”

General positioning:

> Hands-on muscle for defenders to secure AI systems in production — across the WAF, the gateway, the app layer, and the SOC.

WAF-edition positioning (when selling to a WAF-heavy audience — same labs, WAF-forward framing):

> From Web Application Firewall Engineer to AI Runtime Security Engineer

This framing is powerful because many infrastructure/security professionals are concerned about AI reducing traditional engineering roles, while AI security expertise is becoming increasingly valuable.