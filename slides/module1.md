# Module 1 — AI Systems for WAF Engineers

© Elephant Scale


---

## Module 1 Agenda

- What are LLMs and how do they differ from normal apps
- AI inference pipelines
- Prompt anatomy and flow
- RAG architecture and vector databases
- Agentic workflows and tool calling
- AI gateways and copilots
- MCP and agent protocols
- Where WAF visibility exists — and where it disappears

---

## What Is a Large Language Model?

An LLM is a statistical model trained to predict the next token in a sequence.

Key properties:
- Input and output are **text** (tokens), not structured data
- No deterministic logic — output is probabilistic
- Behavior is shaped by training data and prompts
- Context window limits how much it "remembers" per request

![](../images/pexels-markus-winkler-1430818-30839680.jpg)

> From a WAF perspective: the payload is natural language, not SQL or HTML.

---

## LLMs vs Traditional Web Apps

| Property | Traditional App | LLM App |
|---|---|---|
| Input type | Structured (forms, JSON) | Freeform text |
| Logic | Deterministic | Probabilistic |
| Attack surface | Known endpoints | Open-ended prompt |
| Output | Predictable | Variable |
| State | Session-managed | Context window |
| Injection | SQL, XSS, LDAP | Prompt injection |

![](../images/pexels-diosajandy-13604888.jpg)
---

## Tokens — The Unit of AI Processing

LLMs don't process characters or words — they process **tokens**.

- A token ≈ 4 characters on average
- "Hello world" = 2 tokens
- `gpt-4o`: 128K token context window
- Tokens drive **cost** and **rate limiting**

Security implication:
- Attackers can craft prompts to maximize token consumption (denial-of-wallet)
- Token limits can be abused to truncate safety instructions


---

## The AI Inference Pipeline

```
User Input
    │
    ▼
[WAF / API Gateway]
    │
    ▼
[AI Gateway / Guardrails]
    │
    ▼
[System Prompt Assembly]
    │
    ▼
[LLM API — Inference]
    │
    ▼
[Output Filtering]
    │
    ▼
User Response


```
![](../images/pexels-pavel-danilyuk-7594196.jpg)

WAF visibility exists at the edges. The middle is often opaque.

---

## Anatomy of a Prompt

A prompt typically has three parts:

**System prompt** — instructions set by the developer
```
You are a helpful customer support agent for Acme Corp.
Never discuss competitor products.
```

**Context** — retrieved documents, history, tool output

**User message** — what the end user typed

Together these form the **full context window** sent to the model.

---

## Why the System Prompt Matters for Security

The system prompt is the developer's primary security control at the model layer.

It can:
- Define the model's role and constraints
- Block certain topics
- Set output format requirements

It cannot:
- Reliably prevent a determined attacker
- Override injected instructions in retrieved content
- Enforce cryptographic guarantees

> The system prompt is a policy document, not a security boundary.

---

## Prompt Flow — From Browser to Model

```
Browser → HTTPS → WAF → API Gateway → App Server
                                           │
                                    System Prompt +
                                    User Message +
                                    RAG Context
                                           │
                                      LLM API
                                           │
                                      Response
                                           │
Browser ← HTTPS ← WAF ← API Gateway ← App Server
```

WAF sees HTTP traffic. It does **not** see what the LLM receives internally.

---

## Streaming APIs — A WAF Complication

Most LLM APIs support **streaming** responses (Server-Sent Events).

```
data: {"choices":[{"delta":{"content":"Hello"}}]}
data: {"choices":[{"delta":{"content":" world"}}]}
data: [DONE]
```

WAF challenges:
- Cannot inspect full response before delivery
- Buffering for inspection defeats latency goals
- Malicious content may arrive in fragments

---

## RAG Architecture Overview

**Retrieval-Augmented Generation** grounds LLM responses in external documents.

```
User Query
    │
    ▼
[Embedding Model] → Query Vector
    │
    ▼
[Vector Database] → Top-K Similar Chunks
    │
    ▼
[Prompt Assembly] ← System Prompt + Chunks + Query
    │
    ▼
[LLM] → Response
```

RAG is now the standard architecture for enterprise AI assistants.

---

## RAG — The Components

| Component | Role | Security Concern |
|---|---|---|
| Document store | Source of truth | Poisoned documents |
| Chunker | Splits docs into pieces | Hidden instructions in chunks |
| Embedding model | Converts text to vectors | Adversarial embeddings |
| Vector database | Stores/retrieves vectors | Unauthorized retrieval |
| Retriever | Finds relevant chunks | Retrieval manipulation |
| Prompt assembler | Builds final prompt | Injection via retrieved text |

---

## Vector Databases

A vector database stores documents as **high-dimensional numerical vectors**.

Popular options: Pinecone, Weaviate, Qdrant, pgvector, Chroma

How retrieval works:
1. Query is converted to a vector by the embedding model
2. Database finds nearest vectors (cosine similarity)
3. Source text for those vectors is returned

Security issue: **nearest neighbor** is a semantic match, not an exact string match — hard to filter with traditional rules.


---

## Embeddings — What They Are

An **embedding** is a vector representation of text that captures semantic meaning.

```
"password reset"  →  [0.23, -0.87, 0.41, ...]
"forgot my pass"  →  [0.21, -0.85, 0.44, ...]  ← similar
"SQL injection"   →  [0.67,  0.12, -0.33, ...]  ← different
```

Why this matters:
- Semantic attacks bypass keyword filters
- Poisoned documents can be designed to be retrieved for specific queries
- Filtering by content requires ML classifiers, not regex

---

## Agentic AI — What Are Agents?

An **AI agent** is an LLM that can take actions, not just answer questions.

Agents can:
- Call APIs and external services
- Read and write files
- Execute code
- Browse the web
- Send emails and messages
- Spawn sub-agents

> The shift from "chatbot" to "agent" is the shift from **read-only** to **read-write** risk.


---

## Agentic Workflow Pattern

```
User Goal: "Research competitors and prepare a report"

Agent Loop:
  1. Think: What do I need to do?
  2. Act:   Call search tool
  3. Observe: Read results
  4. Think: What's next?
  5. Act:   Call file write tool
  6. Observe: Success
  7. Think: Done — return report
```

Each **Act** step is a real action with real consequences.
WAF may see some of these API calls — but not the agent's reasoning.

---

## Tool Calling

LLMs request tools using structured output:

```json
{
  "tool": "send_email",
  "parameters": {
    "to": "admin@example.com",
    "subject": "Report",
    "body": "..."
  }
}
```

The application executes the tool and returns results to the model.

Security risk: An attacker who controls the prompt can influence **which tools are called with what parameters**.

---

## Tool Calling — The Attack Surface

```
Attacker Input (prompt)
        │
        ▼ (prompt injection)
    LLM decides to call tools
        │
        ▼
    [send_email]  [delete_file]  [POST /api/admin]
        │
        ▼
    Real world impact
```

WAF sees the HTTP requests the agent makes — but may not know they originated from an attacker-controlled prompt.

---

## Multi-Agent Architectures

Modern AI systems often chain multiple agents:

```
Orchestrator Agent
    ├── Research Agent
    ├── Code Agent
    ├── File Agent
    └── Communication Agent
```

Attack implications:
- An attacker injecting into one agent can propagate to others
- Agent-to-agent calls may bypass WAF entirely (internal network)
- Trust boundaries between agents are often undefined


---

## Copilots — The Business Context

A **copilot** is an AI assistant embedded in a business workflow.

Examples:
- GitHub Copilot (code completion)
- Microsoft 365 Copilot (email, calendar, documents)
- Salesforce Einstein (CRM)
- Custom enterprise chatbots

From a WAF perspective:
- Copilots access sensitive internal data via APIs
- They act on behalf of users — often with elevated permissions
- They are prime targets for indirect prompt injection

---

## AI Gateways

An **AI gateway** sits between your application and LLM providers.

Functions:
- Route requests to different models
- Apply prompt/response filtering
- Enforce rate limits (token-based)
- Log all prompts and completions
- Apply guardrails and classifiers
- Manage API keys and quotas

Examples: AWS Bedrock, Azure AI Studio, Cloudflare AI Gateway, Kong AI Gateway, Portkey, LiteLLM


---

## AI Gateway vs Traditional WAF

| Capability | WAF | AI Gateway |
|---|---|---|
| HTTP filtering | ✓ | ✓ |
| Rate limiting | ✓ (request-based) | ✓ (token-based) |
| Prompt inspection | ✗ | ✓ |
| Response filtering | Limited | ✓ |
| Semantic analysis | ✗ | ✓ |
| Model routing | ✗ | ✓ |
| Cost enforcement | ✗ | ✓ |

WAF and AI gateway are **complementary**, not alternatives.

---

## MCP — Model Context Protocol

**MCP** (Anthropic, 2024) is an open protocol for connecting LLMs to external tools and data.

```
LLM Client (Claude, GPT)
        │  MCP Protocol
        ▼
MCP Server (exposes tools + resources)
        │
        ▼
Real systems: files, databases, APIs, services
```

MCP is becoming the standard for agent tool connectivity — analogous to USB for peripherals.


---

## MCP Security Concerns

MCP introduces new attack surfaces:

- **Tool poisoning** — malicious MCP server exposes dangerous tools
- **Resource injection** — MCP resource returns attacker-controlled text
- **Privilege escalation** — agent inherits MCP server's permissions
- **Confused deputy** — agent acts on behalf of attacker via MCP

WAF relevance:
- MCP uses HTTP/SSE transport — WAF can inspect at the transport layer
- Content inspection of MCP payloads requires custom rules

---

## Agent Protocols — The Ecosystem

| Protocol | Purpose | Transport |
|---|---|---|
| MCP | Tool/resource connectivity | HTTP, SSE, stdio |
| OpenAI function calling | Tool use | JSON over HTTPS |
| LangChain tools | Framework tool abstraction | Various |
| A2A (Google) | Agent-to-agent | HTTP |
| AutoGen | Multi-agent orchestration | Internal |

Most use HTTP — WAF has transport-layer visibility.
Semantic content requires AI-aware inspection.

---

## Where WAF Visibility Exists

WAF **can** see and control:

- Initial HTTP request to AI endpoint (`/v1/chat/completions`)
- Request headers, source IP, auth tokens
- Request body (prompt as raw text)
- Response body (before delivery to client)
- HTTP method, status codes, response size
- Tool call HTTP requests made by agents
- Rate limiting by request count or token estimate

---

## Where WAF Visibility Disappears

WAF **cannot** see:

- What the LLM reasons internally
- Injected instructions hidden inside retrieved documents
- Agent-to-agent calls over internal networks
- Content inside encrypted sub-requests
- Semantic meaning of obfuscated prompts
- Multi-turn context accumulating across requests
- Decisions made by the model about tool use

> The WAF sees the envelope. It does not see how the model interprets the letter inside.


---

## The Visibility Gap

```
VISIBLE TO WAF                    NOT VISIBLE TO WAF
─────────────────────             ──────────────────────
HTTP headers                      Model reasoning
Raw prompt text                   Semantic meaning
Token count (approx)              Retrieved document content
Response body                     Agent internal state
Source IP / auth                  Multi-turn context
Outbound agent API calls          Why a tool was called
```

Bridging this gap requires **AI gateways + guardrails** working alongside WAF.

---

## The New Attack Surface

```
[Browser / Client]
       │  ← WAF covers this
[API Gateway / WAF]
       │
[Application Server]
       │  ← Prompt injection here
[Prompt Assembly]
       │  ← RAG poisoning here
[Vector DB / Documents]
       │
[LLM Inference]        ← Model manipulation
       │
[Tool Execution]       ← Agent abuse here
       │
[External Services]    ← Data exfiltration here
```

---

## Mapping Architecture to Threats

| Component | Primary Threat |
|---|---|
| HTTP endpoint | DDoS, scraping, auth bypass |
| System prompt | Prompt injection, override |
| User input | Direct prompt injection, jailbreak |
| RAG / vector DB | Document poisoning, retrieval manipulation |
| LLM model | Model extraction, adversarial inputs |
| Tool execution | Unauthorized actions, privilege escalation |
| Output | Sensitive data disclosure, indirect injection |

---

## Traditional vs AI Threat Models

**Traditional WAF mindset:**
- Attack is in the HTTP request
- Block malicious patterns
- Enforce allow/deny rules

**AI WAF mindset:**
- Attack may be in retrieved documents, not the request
- Semantic intent matters, not just syntax
- The model itself can be the attack vector
- Output can carry attacks downstream


---

## Key Architectural Patterns You Will Defend

Over this course you will build defenses for:

1. **Chatbot APIs** — prompt injection at the HTTP layer
2. **RAG pipelines** — document poisoning and retrieval abuse
3. **Agentic systems** — tool abuse and privilege escalation
4. **LLM APIs** — denial-of-wallet and model scraping
5. **Copilot integrations** — indirect injection through business data
6. **Multi-agent workflows** — cross-agent propagation attacks

---

## Module 1 Summary

- LLMs are probabilistic, token-based systems — not deterministic apps
- AI inference pipelines have multiple layers, each with its own attack surface
- RAG adds document retrieval as a new injection vector
- Agents transform AI from read-only to read-write risk
- Tool calling gives attackers a path from text to real-world actions
- WAF visibility is strong at HTTP boundaries, weak inside the AI stack
- AI gateways and guardrails extend WAF coverage into the semantic layer

---

## What's Next

**Module 2 — OWASP GenAI Top 10**

We move from architecture to the specific attack categories:
- Prompt Injection
- Insecure Output Handling
- Training Data Poisoning
- Model DoS
- And six more...

---

## Lab Preview — Lab 1

**Attack a chatbot with prompt injection**

You will:
1. Interact with an intentionally vulnerable AI chatbot
2. Attempt to override its system prompt
3. Extract hidden instructions
4. Observe what basic WAF rules catch — and what they miss

Environment: provided Docker-based lab
Time: 45 minutes

---