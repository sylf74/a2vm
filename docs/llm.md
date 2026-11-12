# Choosing the LLM of a tenant (v0.23.8)

A2VM speaks to any OpenAI-compatible endpoint (vLLM, SGLang, a cloud service): the model is the
tenant's choice. A client may refuse a model of some origin, or want one it already approved. What
changes from one model to another is how it reasons before answering: a reasoning model writes a
long chain of thought before its JSON, many times slower for the short answers A2VM asks for. Since
v0.23.8 one setting, `reasoning`, is sent the way each family takes it. Design: LLD triage §7.0.

## 1. Settings

CI/CD variables of the group or of the tenant project (passed to the cluster by `deploy-k8s`), or
`llm` in `settings.yaml`:

| Variable | Setting | Values |
| --- | --- | --- |
| `A2VM_LLM_ENABLED` | `llm.enabled` | `true` once the endpoint answers |
| `A2VM_LLM_BASE_URL` | `llm.base_url` | the endpoint(s), `http://llm.lab.example:8000/v1`; several comma-separated (LLD triage §7.1) |
| `A2VM_LLM_MODEL` | `llm.model` | the model's name as the server serves it |
| `A2VM_LLM_FAMILY` | `llm.family` | `qwen3`, `gemma`, `gpt-oss`, `mistral`, `generic`; empty: found from the model's name |
| `A2VM_LLM_REASONING` | `llm.reasoning` | `off`, `low`, `medium`, `high`; empty: the model's default |
| `A2VM_LLM_THINKING` | `llm.thinking` | v0.23.7, Qwen3 only (`off`, `on`); `A2VM_LLM_REASONING` wins when both are set |

How each family takes the level:

| Family | Found in the name | Sent | `off` | `low`, `medium`, `high` |
| --- | --- | --- | --- | --- |
| `qwen3` | `qwen3` | `chat_template_kwargs.enable_thinking` | `false` | `true` |
| `gemma` | `gemma-4`, `gemma4` | `chat_template_kwargs.enable_thinking` | `false` | `true` |
| `gpt-oss` | `gpt-oss` | `reasoning_effort` | `low` (gpt-oss has no off) | the level |
| `mistral` | `mistral`, `magistral` | `reasoning_effort` | `none` | `high` |
| `generic` | anything else | nothing | - | - |

For the triage and the watch, `off` is the right level: the answers are short, the SSVC tables
decide (D4), and the guard checks every rationale. The job log says what each job received:
`LLM: enabled, base_url=…, model=…, family gpt-oss, reasoning off`.

## 2. Models known to work with A2VM

All under Apache 2.0, served by vLLM. The memory is the order of magnitude for the weights; the
context (`--max-model-len`) takes the rest.

| Model | Origin | Size | 16 GiB GPU (RTX A4000) | 128 GiB (DGX Spark) |
| --- | --- | --- | --- | --- |
| `openai/gpt-oss-20b` | United States | MoE 21B, 3.6B active | Yes, as published (MXFP4) | Yes |
| `openai/gpt-oss-120b` | United States | MoE 117B, 5.1B active | No | Yes |
| `mistralai/Mistral-Small-4-2603` | France | MoE 119B, 6.5B active | No | In 4 bits |
| Gemma 4 26B MoE (`google/gemma-4-…`) | United States | MoE 26B, 3.8B active | In 4 bits, short context | Yes |
| `Qwen/Qwen3-14B` (AWQ) | China | dense 14B | Yes | Yes |

The analysts' chat (Open WebUI, `docs/chat.md`) calls tools: vLLM must be started with the tool
parser of the family. The flags below are those of the vLLM recipes at the time of writing: check
them against the recipe of the vLLM version deployed.

| Family | vLLM flags |
| --- | --- |
| gpt-oss | `--tool-call-parser openai --enable-auto-tool-choice` |
| qwen3 | `--reasoning-parser qwen3 --tool-call-parser hermes --enable-auto-tool-choice` |
| mistral | `--tokenizer-mode mistral --config-format mistral --load-format mistral --tool-call-parser mistral --enable-auto-tool-choice` |
| gemma | the parser named in the vLLM recipe of Gemma 4 |

## 3. Changing the model

1. Start the new model on the inference server (or a second endpoint beside the first).
2. Set `A2VM_LLM_MODEL` (and `A2VM_LLM_BASE_URL` if it moved), and `A2VM_LLM_REASONING=off`, on
   the group or the tenant project; push the tenant project (`deploy-k8s`).
3. The LLM cache (`/data/llm-cache.json`) keys its answers by model: the first run with the new
   model asks everything once, the next ones only what changed.
4. Check, before telling the client:
   - the daily job log: `llm_fallbacks` (rationales the guard rejected) close to 0, and the line
     `LLM: <n> questions, …` with a reasonable time;
   - the chat: the questions of `tests/chat-questions.yaml` in Open WebUI, each answered with the
     tool it names;
   - a few rationales of ACT decisions (« Pourquoi la CVE-… est-elle en ACT sur … ? »).

The decisions do not depend on the model (D4): changing it changes the rationales, the SSVC inputs
estimated for CVEs without CVSS, the product matches it confirms, and the chat's answers.

## 4. The user forwarded by the chat (v0.23.11)

Open WebUI sends the user who asks (name, id, e-mail, role, headers `X-OpenWebUI-User-*`) with each
call to the tool server, which writes it in the audit journal (`get_audit`, v0.23.10). Open WebUI
sends the same headers with each call to the LLM endpoints. With a model the tenant runs, they stay
in its network. With a SaaS LLM, the provider receives the analysts' e-mails.

| Variable (`deploy-k8s`) | Chart value | Values |
| --- | --- | --- |
| `A2VM_CHAT_FORWARD_USER_INFO` | `chat.forwardUserInfo` | `true` (default), `false` |

With `false`, Open WebUI sends no user header: the journal reads `chat (user not forwarded)` for the
chat's calls. The validations on the review page keep their author (OIDC).

