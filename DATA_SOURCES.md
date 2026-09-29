# Data and model sources

Every public dataset and model this repo downloads, pinned to a Hugging Face
commit. Licenses and gating were checked on 2026-09-28 against each dataset or
model card and the Hugging Face API (`cardData.license`, `gated`). None of the
sources below is gated. File hashes are in `data/sources.lock.json` and
`gateway fetch` verifies them.

## Datasets

| Dataset | Revision | License | Used for | URL |
|---|---|---|---|---|
| Tallowbrook Neobank Support (synthetic) | `3c72058` (git) | CC-BY-4.0 | Help-center corpus, RAG questions (benign traffic, indirect-attack carriers) | Vendored in `data/tallowbrook/`. Its canonical home is planned as a Hugging Face dataset. |
| `deepset/prompt-injections` | `4f61ecb038e9c3fb77e21034b22511b523772cdd` | Apache-2.0 | Direct injections (rows labelled 1) | https://huggingface.co/datasets/deepset/prompt-injections |
| `JailbreakBench/JBB-Behaviors` | `886acc352a31533ffbcf4ef22c744658688086fc` | MIT | Harmful-request goals (`harmful-behaviors.csv`) | https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors |
| `Lakera/gandalf_ignore_instructions` | `04737b65e90a6794ec227012e4a255a7def6344b` | MIT | Direct injections | https://huggingface.co/datasets/Lakera/gandalf_ignore_instructions |
| `microsoft/llmail-inject-challenge` | `1063bdf01ec8762b812d5e06ee768a06faa5a6f7` | MIT | Indirect injections (phase-2 submissions that met every objective), benign documents (`emails_for_fp_tests.json`) | https://huggingface.co/datasets/microsoft/llmail-inject-challenge |
| `leolee99/NotInject` | `847ae76cf8fea5ed325429e569ae8cfef022d2e0` | MIT | Benign prompts full of trigger words | https://huggingface.co/datasets/leolee99/NotInject |
| `legacy-datasets/banking77` | `f54121560de48f2852f90be299010d1d6dc612ec` | CC-BY-4.0 | Benign in-domain prompts (test split) | https://huggingface.co/datasets/legacy-datasets/banking77 |
| `gretelai/synthetic_pii_finance_multilingual` | `7b844d16738527a04264f50214cb426a4cea0897` | Apache-2.0 | PII benchmark (English rows of the test split) | https://huggingface.co/datasets/gretelai/synthetic_pii_finance_multilingual |
| `nvidia/Nemotron-PII` | `b70ffaf5ff39e079776134c5bf4381f00a9fd1ed` | CC-BY-4.0 | PII benchmark (seeded sample of US-locale test rows) | https://huggingface.co/datasets/nvidia/Nemotron-PII |

Notes from the checks:

- `deepset/prompt-injections`: the card's top-level license is Apache-2.0 and a
  nested `dataset_info` block also says CC-BY-4.0. Both allow redistribution
  with attribution, which this file provides.
- `JailbreakBench/JBB-Behaviors`: MIT. Some behaviors come from AdvBench and
  the Trojan Detection Challenge / HarmBench, which the card cites and which
  are also MIT. Only the `Goal` column is used.
- `gretelai/synthetic_pii_finance_multilingual`: Apache-2.0, "can be used for
  any purpose that is not harmful". The card says labels came from a NER
  library plus an LLM judge, so some gold spans are wrong or missing.
- `microsoft/llmail-inject-challenge`: MIT. The raw phase-2 file is 263 MB and
  is not committed. Only the 121 payloads selected for the suite are.
- `nvidia/Nemotron-PII`: CC-BY-4.0, "ready for commercial use". Not committed,
  only per-document match counts are.

## Frozen suites in this repo

`data/suites/attacks.jsonl` and `data/suites/benign.jsonl` redistribute rows
from the datasets above. Each row carries `source`, `source_revision`,
`source_row` and `license`. The mechanical transforms (base64, leetspeak,
Cyrillic homoglyphs, zero-width spaces, a code fence) are applied by
`src/guarded_llm_gateway/eval/transforms.py`, and no attack text was written
by hand.

## Training-data overlap

Public attack sets can be in a detector's training data, which inflates its
recall on them.

- PIGuard was trained on the deepset train split. The InjecGuard paper (arXiv
  2410.22770, Tables 4 and 5) lists `prompt-injections` from Deepset with 343
  benign and 203 injection samples, which add up to the 546 rows of that split.
  Most deepset rows in this suite come from the train split (`source_row` starts
  with `train:`), so PIGuard's recall on the deepset rows is optimistic. The
  same paper introduced NotInject as an evaluation-only set.
- ProtectAI's v2 card lists its training datasets. None of the sources above
  is on that list.
- Neither card lists Gandalf, JailbreakBench or LLMail-Inject.

## Models

| Model | Revision | License | Parameters | Role |
|---|---|---|---|---|
| `leolee99/PIGuard` | `dd78b24e330193a22d2293ac66922dd4f982f563` | MIT | 184M | Injection detector |
| `protectai/deberta-v3-base-prompt-injection-v2` | `90c9989b1a342275dd0d1a95aad283c04e075671` | Apache-2.0 | 184M | Injection detector baseline |
| spaCy `en_core_web_sm` | 3.8.0 (GitHub release wheel) | MIT | about 12 MB | NER for Presidio |

Not used: `meta-llama/Llama-Prompt-Guard-2-22M` is gated under the Llama 4
Community License, so it is left out.
