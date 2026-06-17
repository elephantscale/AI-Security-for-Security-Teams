# AI Security for WAF Specialists
© Elephant Scale

June 16, 2026

## Course Description

This course teaches Web Application Firewall (WAF) specialists how to secure modern AI-powered applications, APIs, copilots, and autonomous agents.

Students learn how traditional web attacks evolve in AI systems, how prompt injection differs from SQL injection, how AI agents abuse tools and APIs, and how WAFs integrate with runtime AI security controls.

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

A normal WAF engineer thinks about:
- XSS
- SQL injection
- CSRF
- API abuse
- rate limiting

An AI security WAF engineer must now think about:
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
AI attacks are often semantic, not merely syntactic.

---

# Audience

- WAF specialists
- API security engineers
- Cloud security engineers
- SOC analysts
- DevSecOps engineers
- Security architects
- AI platform engineers
- Security operations teams

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
- Protect LLM APIs with WAF controls
- Build AI-aware rate limiting
- Identify prompt injection attempts
- Secure RAG architectures
- Defend agentic AI systems
- Monitor AI abuse patterns
- Design layered AI defenses
- Integrate WAFs with AI gateways and guardrails

---

# Module 1 — AI Systems for WAF Engineers

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
- mapping to WAF controls
- where WAF helps
- where WAF fails

---

# Module 3 — Prompt Injection Detection

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
- traditional WAF vs AI gateway
- proxy-based vs semantic filtering

---

# Module 10 — Building a Layered AI Defense

Important philosophical conclusion:

A WAF alone cannot secure AI.

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

## Example Labs

### Lab 1
Attack a chatbot with prompt injection

### Lab 2
Bypass naïve AI filtering

### Lab 3
Build AI-aware WAF rules

### Lab 4
Poison a RAG pipeline

### Lab 5
Detect denial-of-wallet attacks

### Lab 6
Secure an autonomous agent

### Lab 7
Monitor AI abuse patterns in logs

### Lab 8
Build layered AI defense architecture

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
“WAF but with AI buzzwords.”

This IS:
“Your WAF team is becoming the runtime security layer for autonomous systems.”

Potential positioning:

> From Web Application Firewall Engineer to AI Runtime Security Engineer

This framing is powerful because many infrastructure/security professionals are concerned about AI reducing traditional engineering roles, while AI security expertise is becoming increasingly valuable.