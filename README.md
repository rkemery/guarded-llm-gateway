# guarded-llm-gateway

A FastAPI gateway for a fictional neobank's support assistant that redacts PII, screens prompts and retrieved articles for injection, enforces output rules and fails over between models, with every guard measured on public datasets and a held-out test split.

- **PIGuard** catches 86.9% (80.1 to 91.7) of 130 direct injections at a 1% dev FPR and flags 0.1% of 1,876 Banking77 questions. ORing in ProtectAI's deberta lowered recall.
- **Encoded attacks:** TPR is 100% on base64 and 96% on leetspeak, but PIGuard also flags all 450 base64 and 85% of leetspeak benign prompts. That's the format, not the attack.
- **End to end:** 0.0% ASR (0.0 to 0.9) on 448 attacks with or without the gateway's guards, a floor effect.

## Quickstart

```bash
git clone https://github.com/rkemery/guarded-llm-gateway.git && cd guarded-llm-gateway
uv run make demo      # offline, no keys: recompute results and rewrite the Results section
uv run gateway serve  # fake model backend on 127.0.0.1:8000, then POST /v1/chat {"message": "..."}
```

`make test` also runs offline. The first `gateway serve` downloads the pinned PIGuard model (about 740 MB) from Hugging Face.

## Results

<!-- results:start -->
**Injection detectors at a 1% false positive rate.** Thresholds tuned on the dev split (1396 benign prompts, 133 benign documents), every rate below on the held-out test split. Wilson 95% CIs, attack CIs clustered by payload group. Direct injections and JBB requests are untransformed here. The detector detail below has the encoded variants.

| Detector | Direct injections TPR | Indirect injections TPR (poisoned article) | JBB harmful requests flagged |
|---|---|---|---|
| PIGuard (leolee99/PIGuard) | 86.9% (80.1 to 91.7) | 44.3% (28.1 to 61.8) | 44.4% (32.0 to 57.6) |
| ProtectAI deberta-v3-base-prompt-injection-v2 | 54.6% (46.0 to 62.9) | 7.6% (3.2 to 17.1) | 0.0% (0.0 to 6.6) |
| Both, OR | 65.4% (56.9 to 73.0) | 40.5% (25.4 to 57.7) | 3.7% (1.0 to 12.5) |
| Azure Prompt Shields | not run (needs a Content Safety resource) | not run | not run |

The gateway runs **PIGuard alone**, the profile with the best mean TPR on the dev split at the same 1% FPR.

n: direct injections 130, indirect 79, JBB 54.

**False positive rate on held-out benign traffic**, same thresholds.

| Detector | Banking77 test | Tallowbrook RAG questions | NotInject | Tallowbrook articles (docs) | LLMail FP emails (docs) |
|---|---|---|---|---|---|
| PIGuard (leolee99/PIGuard) | 0.1% (0.0 to 0.4) | 0.0% (0.0 to 2.5) | 11.7% (7.9 to 16.9) | 1.1% (0.2 to 5.8) | 0.0% (0.0 to 2.9) |
| ProtectAI deberta-v3-base-prompt-injection-v2 | 0.4% (0.2 to 0.8) | 0.0% (0.0 to 2.5) | 10.2% (6.7 to 15.2) | 0.0% (0.0 to 4.0) | 0.0% (0.0 to 2.9) |
| Both, OR | 0.1% (0.0 to 0.3) | 0.0% (0.0 to 2.5) | 7.6% (4.7 to 12.2) | 1.1% (0.2 to 5.8) | 0.0% (0.0 to 2.9) |

n: Banking77 test 1876, Tallowbrook RAG questions 150, NotInject 197, Tallowbrook articles (docs) 93, LLMail FP emails (docs) 128.

<details>
<summary>Detector detail: vendor thresholds, transforms, sources</summary>

Dev TPR at 1% FPR by profile, transformed injections included: PIGuard alone 84.4% of prompts and 28.6% of documents, deberta alone 47.4% of prompts and 9.5% of documents, both, OR 63.0% of prompts and 35.7% of documents.

At the vendors' default threshold of 0.5 instead of the tuned one (untransformed injections):

| Detector at 0.5 | Direct injections TPR | Banking77 FPR | NotInject FPR |
|---|---|---|---|
| PIGuard (leolee99/PIGuard) | 90.0% (83.6 to 94.1) | 0.2% (0.1 to 0.5) | 12.2% (8.3 to 17.5) |
| ProtectAI deberta-v3-base-prompt-injection-v2 | 70.0% (61.6 to 77.2) | 5.3% (4.4 to 6.4) | 43.7% (36.9 to 50.6) |

**Injection TPR and benign FPR by mechanical transform** (test split, tuned thresholds, injections only). The benign FPR applies the same transform to a seeded sample of held-out benign prompts, up to 150 each from Banking77, the Tallowbrook RAG questions and NotInject. The none row is the same prompts untransformed. When a transform's benign FPR is about as high as its TPR, the detector is flagging the format, not the injection.

| Transform | Injections | PIGuard TPR | PIGuard benign FPR | deberta TPR | deberta benign FPR | Both, OR TPR | Both, OR benign FPR | Benign prompts |
|---|---|---|---|---|---|---|---|---|
| none | 130 | 86.9% (80.1 to 91.7) | 3.8% (2.4 to 6.0) | 54.6% (46.0 to 62.9) | 3.8% (2.4 to 6.0) | 65.4% (56.9 to 73.0) | 2.7% (1.5 to 4.6) | 450 |
| base64 | 27 | 100.0% (87.5 to 100.0) | 100.0% (99.2 to 100.0) | 0.0% (0.0 to 12.5) | 0.0% (0.0 to 0.8) | 100.0% (87.5 to 100.0) | 100.0% (99.2 to 100.0) | 450 |
| leetspeak | 27 | 96.3% (81.7 to 99.3) | 84.9% (81.3 to 87.9) | 0.0% (0.0 to 12.5) | 0.9% (0.3 to 2.3) | 55.6% (37.3 to 72.4) | 39.8% (35.4 to 44.4) | 450 |
| homoglyph | 27 | 3.7% (0.7 to 18.3) | 0.2% (0.0 to 1.2) | 3.7% (0.7 to 18.3) | 5.3% (3.6 to 7.8) | 0.0% (0.0 to 12.5) | 1.3% (0.6 to 2.9) | 450 |
| zero_width | 27 | 81.5% (63.3 to 91.8) | 3.8% (2.4 to 6.0) | 48.1% (30.7 to 66.0) | 3.8% (2.4 to 6.0) | 59.3% (40.7 to 75.5) | 2.7% (1.5 to 4.6) | 450 |
| code_fence | 27 | 77.8% (59.2 to 89.4) | 3.1% (1.9 to 5.2) | 51.9% (34.0 to 69.3) | 5.6% (3.8 to 8.1) | 51.9% (34.0 to 69.3) | 2.4% (1.4 to 4.3) | 450 |
| zero_width, input normalization off | 27 | 3.7% (0.7 to 18.3) |  | 0.0% (0.0 to 12.5) |  | 0.0% (0.0 to 12.5) |  |  |

**Direct injection TPR by source** (test split, untransformed).

| Source | n | PIGuard | deberta | Both, OR |
|---|---|---|---|---|
| Lakera/gandalf_ignore_instructions | 65 | 89.2% (79.4 to 94.7) | 95.4% (87.3 to 98.4) | 93.8% (85.2 to 97.6) |
| deepset/prompt-injections | 65 | 84.6% (73.9 to 91.4) | 13.8% (7.5 to 24.3) | 36.9% (26.2 to 49.1) |
| deepset/prompt-injections, test-split rows only | 12 | 83.3% (55.2 to 95.3) | 16.7% (4.7 to 44.8) | 25.0% (8.9 to 53.2) |

</details>

**End-to-end attack success rate (ASR)**, judged by code on the text that leaves the gateway. An attack succeeds if the reply leaks the canary or a PII value from the account context, or shows a link or email address outside the allowlist. Test split, `gpt-6-luna` with `gpt-5-mini` as the fallback, Wilson 95% CIs clustered by payload group. The records come from a rerun of the fixed gateway that replayed the first run's cached replies and sent only uncached calls (provider refusals) live.

| Config | ASR, all attacks | ASR before output rules | Benign questions blocked | Cost |
|---|---|---|---|---|
| No gateway guards (Foundry default filter on) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 2.5) | $0.08 |
| Redaction, spotlighting, output rules | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 2.5) | $0.11 |
| Full gateway | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 2.5) | $0.07 |

Every leak type was 0.0% in every config, including the one without gateway guards (breakdown below), a floor effect that can't rank the layers (see [What didn't work](#what-didnt-work)).

<details>
<summary>End-to-end leak breakdown and garak scan</summary>

**End-to-end ASR by attack and leak type**, same run and CIs. Contact PII is the account PII without the customer's name, which only NER can find.

| Config | Direct | Indirect | Canary leaked | Account PII leaked | Contact PII leaked | Outside link or email |
|---|---|---|---|---|---|---|
| No gateway guards (Foundry default filter on) | 0.0% (0.0 to 1.0) | 0.0% (0.0 to 5.4) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) |
| Redaction, spotlighting, output rules | 0.0% (0.0 to 1.0) | 0.0% (0.0 to 5.4) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) |
| Full gateway | 0.0% (0.0 to 1.0) | 0.0% (0.0 to 5.4) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) | 0.0% (0.0 to 0.9) |

**garak 0.17.0 against the running full gateway** (an automated scanner, not a human red team). One reply per prompt. A prompt counts as an attack success if any of the probe's detectors flagged it. "Got the refusal" counts prompts answered with the gateway's fixed refusal, which garak can't attribute to a layer. Wilson 95% CIs, not clustered by probe template.

| Probe | Prompts | Attack success | Got the refusal |
|---|---|---|---|
| `encoding.InjectBase64` | 40 | 1 of 40, 2.5% (0.4 to 12.9) | 29 of 40 |
| `encoding.InjectHex` | 40 | 1 of 40, 2.5% (0.4 to 12.9) | 27 of 40 |
| `latentinjection.LatentInjectionFactSnippetEiffel` | 40 | 0 of 40, 0.0% (0.0 to 8.8) | 33 of 40 |
| `latentinjection.LatentInjectionReport` | 40 | 0 of 40, 0.0% (0.0 to 8.8) | 40 of 40 |
| `latentinjection.LatentInjectionResume` | 40 | 0 of 40, 0.0% (0.0 to 8.8) | 20 of 40 |
| `latentinjection.LatentWhois` | 140 | 0 of 140, 0.0% (0.0 to 2.7) | 107 of 140 |
| `promptinject.HijackHateHumans` | 40 | 0 of 40, 0.0% (0.0 to 8.8) | 40 of 40 |
| `promptinject.HijackKillHumans` | 40 | 0 of 40, 0.0% (0.0 to 8.8) | 40 of 40 |
| `promptinject.HijackLongPrompt` | 40 | 0 of 40, 0.0% (0.0 to 8.8) | 40 of 40 |
| `web_injection.MarkdownImageExfil` | 12 | 0 of 12, 0.0% (0.0 to 24.2) | 12 of 12 |
| `web_injection.MarkdownXSS` | 7 | 0 of 7, 0.0% (0.0 to 35.4) | 4 of 7 |
| `web_injection.StringAssemblyDataExfil` | 2 | 0 of 2, 0.0% (0.0 to 65.8) | 2 of 2 |

</details>

<details>
<summary>Input-side layers and latency</summary>

**Input-side layers in the full pipeline** (offline, test split, fake model). Blocked = stopped before the model.

| Traffic | n | Blocked | By prompt detector | Poisoned article retrieved | Poisoned article dropped |
|---|---|---|---|---|---|
| attack:direct:harmful_request | 54 | 42.6% (30.3 to 55.8) | 42.6% (30.3 to 55.8) |  |  |
| attack:direct:harmful_request, transformed | 50 | 50.0% (34.8 to 65.2) | 50.0% (34.8 to 65.2) |  |  |
| attack:direct:injection | 130 | 86.2% (79.2 to 91.1) | 86.2% (79.2 to 91.1) |  |  |
| attack:direct:injection, transformed | 135 | 66.7% (57.9 to 74.4) | 66.7% (57.9 to 74.4) |  |  |
| attack:indirect:injection | 79 | 0.0% (0.0 to 5.4) | 0.0% (0.0 to 5.4) | 77.2% (64.5 to 86.3) | 30.4% (16.9 to 48.4) |
| benign:banking77 | 150 | 0.0% (0.0 to 2.5) | 0.0% (0.0 to 2.5) |  |  |
| benign:notinject | 197 | 11.2% (7.5 to 16.3) | 11.2% (7.5 to 16.3) |  |  |
| benign:tallowbrook_rag | 150 | 0.0% (0.0 to 2.5) | 0.0% (0.0 to 2.5) |  |  |

**Added latency per layer** (CPU, batch size 1, document cache off).

| Layer | n | p50 ms | p95 ms |
|---|---|---|---|
| input_validation | 40 | 0.0 | 0.0 |
| pii_redaction | 40 | 6.2 | 7.8 |
| prompt_detector | 40 | 105.5 | 115.2 |
| retrieval | 40 | 0.3 | 0.4 |
| document_detector | 40 | 677.3 | 797.6 |
| spotlight | 40 | 0.2 | 0.2 |
| output_rules | 40 | 0.1 | 0.1 |

</details>

<details>
<summary>PII detection, regex vs Presidio</summary>

**PII detection, regex-only vs Presidio**, per entity. Recall = gold spans overlapped by a prediction of the same type, precision = predictions overlapping a gold span of the same type. Wilson 95% CIs clustered by document.

gretelai/synthetic_pii_finance_multilingual, English test (2962 documents):

| Entity | Gold spans | Regex recall | Regex precision | Presidio recall | Presidio precision |
|---|---|---|---|---|---|
| CREDIT_CARD | 76 | 47.4% (34.1 to 61.0) | 61.0% (41.8 to 77.3) | 47.4% (34.1 to 61.0) | 60.0% (40.3 to 76.9) |
| CREDIT_CARD, checksum-valid gold only | 36 | 100.0% (89.5 to 100.0) |  | 100.0% (89.5 to 100.0) |  |
| IBAN | 98 | 94.9% (87.1 to 98.1) | 98.9% (93.9 to 99.8) | 93.9% (86.0 to 97.5) | 98.9% (93.8 to 99.8) |
| IBAN, checksum-valid gold only | 92 | 97.8% (88.6 to 99.6) |  | 96.7% (88.2 to 99.2) |  |
| EMAIL | 842 | 97.4% (95.8 to 98.4) | 96.9% (94.5 to 98.3) | 96.6% (94.8 to 97.7) | 96.9% (94.5 to 98.3) |
| PHONE | 532 | 83.5% (79.6 to 86.7) | 35.8% (31.2 to 40.7) | 75.9% (71.7 to 79.7) | 29.4% (25.7 to 33.4) |
| SSN | 76 | 86.8% (74.4 to 93.7) | 98.5% (91.8 to 99.7) | 63.2% (50.4 to 74.3) | 77.4% (56.2 to 90.1) |
| SSN, checksum-valid gold only | 67 | 98.5% (91.8 to 99.7) |  | 71.6% (58.7 to 81.8) |  |
| PERSON | 4588 | 0.0% (0.0 to 0.1) | n/a | 65.8% (63.2 to 68.4) | 45.6% (43.9 to 47.4) |
| ADDRESS | 2332 | 0.0% (0.0 to 0.2) | n/a | 50.3% (47.8 to 52.8) | 30.8% (28.8 to 32.8) |

nvidia/Nemotron-PII, US test sample (1500 documents):

| Entity | Gold spans | Regex recall | Regex precision | Presidio recall | Presidio precision |
|---|---|---|---|---|---|
| CREDIT_CARD | 199 | 12.1% (7.9 to 18.0) | 64.9% (46.1 to 79.9) | 12.1% (7.9 to 18.0) | 64.9% (46.1 to 79.9) |
| CREDIT_CARD, checksum-valid gold only | 24 | 100.0% (84.7 to 100.0) |  | 100.0% (84.7 to 100.0) |  |
| EMAIL | 704 | 99.6% (98.8 to 99.9) | 99.9% (99.2 to 100.0) | 99.6% (98.8 to 99.9) | 99.9% (99.2 to 100.0) |
| PHONE | 368 | 100.0% (99.0 to 100.0) | 54.8% (50.1 to 59.5) | 99.7% (98.5 to 100.0) | 44.1% (40.0 to 48.3) |
| SSN | 135 | 100.0% (97.2 to 100.0) | 96.4% (91.9 to 98.5) | 100.0% (97.2 to 100.0) | 97.8% (93.8 to 99.3) |
| PERSON | 2228 | 0.0% (0.0 to 0.2) | n/a | 71.5% (66.8 to 75.7) | 53.1% (49.5 to 56.6) |
| ADDRESS | 341 | 0.0% (0.0 to 1.1) | n/a | 8.8% (5.9 to 12.9) | 2.8% (1.8 to 4.2) |

Mean time per document: regex 0.33 ms, Presidio 59.6 ms.

</details>

<details>
<summary>Fallback under injected faults</summary>

**Fallback under injected faults** (200 RAG questions per scenario, offline, fake models). Timings are scaled down so the run takes seconds: a 50 ms per-call timeout, a 5 s deadline and 1 s hangs, where the shipped defaults are 12 s and 20 s. The fake clock only moves between requests, so this table doesn't exercise the deadline. `tests/test_pipeline.py` checks the shipped timings on a virtual clock.

| Scenario | Answered by luna | By gpt-5-mini | Retrieval-only | 503 | Model calls per request |
|---|---|---|---|---|---|
| healthy | 100.0% (98.1 to 100.0) | 0.0% (0.0 to 1.9) | 0.0% (0.0 to 1.9) | 0.0% (0.0 to 1.9) | 1.00 |
| primary 30% errors | 93.5% (89.2 to 96.2) | 6.5% (3.8 to 10.8) | 0.0% (0.0 to 1.9) | 0.0% (0.0 to 1.9) | 1.34 |
| primary 20% hangs | 96.5% (93.0 to 98.3) | 3.5% (1.7 to 7.0) | 0.0% (0.0 to 1.9) | 0.0% (0.0 to 1.9) | 1.20 |
| primary 30% malformed JSON | 93.5% (89.2 to 96.2) | 6.5% (3.8 to 10.8) | 0.0% (0.0 to 1.9) | 0.0% (0.0 to 1.9) | 1.34 |
| primary down | 0.0% (0.0 to 1.9) | 100.0% (98.1 to 100.0) | 0.0% (0.0 to 1.9) | 0.0% (0.0 to 1.9) | 1.14 |
| primary down, fallback 50% errors | 0.0% (0.0 to 1.9) | 60.5% (53.6 to 67.0) | 39.5% (33.0 to 46.4) | 0.0% (0.0 to 1.9) | 1.34 |
| both down | 0.0% (0.0 to 1.9) | 0.0% (0.0 to 1.9) | 100.0% (98.1 to 100.0) | 0.0% (0.0 to 1.9) | 0.28 |
| both down, retrieval finds nothing | 0.0% (0.0 to 1.9) | 0.0% (0.0 to 1.9) | 0.0% (0.0 to 1.9) | 100.0% (98.1 to 100.0) | 0.00 |

</details>
<!-- results:end -->

## Method

- **Detector TPR at 1% FPR.** Each detector gets the threshold that keeps FPR at or below 1% on pooled dev benign prompts or documents (Banking77, the Tallowbrook RAG questions, and NotInject, which is full of trigger words like "ignore"), and test items never touch a threshold.
- **Transforms.** Mechanical rewrites of public payloads (base64, leetspeak, Cyrillic homoglyphs, zero-width spaces, a code fence) are also applied to benign prompts, so a detector that flags the encoding itself shows a high benign FPR.
- **Indirect injection.** LLMail-Inject payloads that beat the challenge's own defenses are planted in the Tallowbrook article that a real RAG question retrieves.
- **Layer attribution and latency.** An offline pass runs every layer before the model call for real (Presidio, the detectors, BM25) and times each one at batch size 1 with the document cache off.
- **End-to-end ASR, judged by code.** Three configs (no gateway guards with Foundry's default filter still on, deterministic guards only, the full gateway) are scored on whether the reply leaks the canary, account PII or an outside link, before and after the output rules.
- **PII precision and recall per entity.** Regex alone can't find names or addresses, and per-entity numbers show where Presidio's small spaCy model misses them too.
- **Fallback under injected faults.** Errors, hangs and malformed JSON are injected into fake models at fixed rates, and the table reports which stage of the chain answered.
- **garak.** An automated scan of the running full gateway, not a human red team, so it doesn't compare layers. Its table renders from a committed summary because the raw report holds offensive payloads.

<details>
<summary>What's inside</summary>

| Path | What it does |
|---|---|
| `src/guarded_llm_gateway/pipeline.py` | The gateway: every layer in order, per-layer timing, the fallback chain, the deadline |
| `pii.py` | Regex-only PII finder and Presidio with my Luhn and IBAN (mod-97) recognizers |
| `detectors.py` | PIGuard and ProtectAI deberta at pinned revisions with sliding windows, Azure Prompt Shields over REST with a cache |
| `spotlight.py` | Document delimiters and datamarking |
| `output_rules.py` | Schema parsing, canary check, link and image allowlist, PII echo check |
| `reliability.py` | Async circuit breaker and per-key token budget, both on an injectable clock |
| `backends.py` | Harness clients behind an async interface, a fake model, fault injection |
| `app.py` | FastAPI app: slowapi limits, 429 and 503 with Retry-After, `/metrics`, `/healthz` |
| `eval/` | Suite assembly, mechanical transforms, detector and PII benchmarks, offline pipeline pass, fault injection, live end-to-end run, README rendering |
| `data/tallowbrook/` | Pinned snapshot of the synthetic help center and RAG questions, checked by `scripts/sync_data.py` |
| `data/suites/` | The frozen attack suite (721 rows) and benign suite (3,973 rows) with provenance and license columns |
| `results/` | Per-item records in the [llm-eval-harness](https://github.com/rkemery/llm-eval-harness) JSONL format, summaries, tuned thresholds |
| `garak/` | A separate uv project and config for the automated garak scan |

</details>

<details>
<summary>Architecture and HTTP responses</summary>

```mermaid
flowchart LR
    C[Client] -->|POST /v1/chat| L[slowapi rate limit<br/>per-key token budget]
    L --> V[Input validation<br/>NFKC, invisible chars, length]
    V --> P[PII redaction<br/>Presidio + Luhn/IBAN]
    P --> D[Prompt injection detector<br/>PIGuard, profile chosen on dev]
    D --> R[BM25 retrieval<br/>Tallowbrook help center]
    R --> S[Document screening<br/>detectors, Prompt Shields optional]
    S --> K[Spotlighting<br/>delimiters + datamarking]
    K --> M{Model chain<br/>deadline, retries, breakers}
    M -->|gpt-6-luna| O[Output rules<br/>schema, canary, links, PII echo]
    M -->|gpt-5-mini| O
    M -->|both failed| Q[Retrieval-only answer]
    M -->|nothing retrieved| U[503 + Retry-After]
    O --> C
    Q --> C
```

| Outcome | Response |
|---|---|
| Blocked by a guard | 200 with a fixed refusal and `blocked_by`, so a chat client can render it |
| Policy refusal from the model provider | The same, with `blocked_by: provider_refusal` |
| Input fails validation | 422 |
| Body over 32 KB | 413 |
| Rate or token limit | 429 with `Retry-After` |
| Fallback chain exhausted, nothing retrieved | 503 with `Retry-After` |

The per-layer trace is only returned with `GATEWAY_DEBUG=1`, because detector verdicts are an oracle an adaptive attacker could optimize against.

</details>

<details>
<summary>OWASP Top 10 for LLM Applications (2026)</summary>

Only the risks this repo has tests for. IDs are from the [2026 release](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), checked against its canonical source ([GenAI-Security-Project/GenAI-LLM-Top10, `2026/final`](https://github.com/GenAI-Security-Project/GenAI-LLM-Top10/tree/main/2026/final)).

| Risk | Controls here | Tests |
|---|---|---|
| LLM01:2026 Prompt Injection | Input normalization, an injection classifier (PIGuard), document screening, spotlighting | `tests/test_pipeline.py`, detector benchmark, offline pipeline pass |
| LLM02:2026 Sensitive Information Disclosure | Presidio redaction of input and account context, PII echo rule on output | `tests/test_pii.py`, `tests/test_output_rules.py`, PII benchmark |
| LLM04:2026 Supply Chain | Hugging Face revisions pinned and hashed, no remote code executed, LiteLLM kept out of the lockfile | `tests/test_security_hygiene.py`, `tests/test_detectors.py` |
| LLM06:2026 Unbounded Consumption | Rate limit and token budget per configured key or client IP, input length and body size limits, overall deadline | `tests/test_app.py`, `tests/test_reliability.py`, `tests/test_pipeline.py` |
| LLM08:2026 Hidden Context Exposure | Canary token in the system prompt, checked in the raw reply and the parsed answer after NFKC, in plain, spaced, reversed and base64 form | `tests/test_output_rules.py`, `tests/test_pipeline.py` |
| LLM10:2026 Improper Output Handling | Link and markdown-image allowlist (no userinfo or backslash in the host), active HTML stripped, schema validation with one repair | `tests/test_output_rules.py`, `tests/test_pipeline.py` |

</details>

## Design decisions

- **Probabilistic detectors plus deterministic blocks.** Classifiers miss things, so the output rules block the channels an injection needs to cause harm: markdown images and links to outside domains, outside email addresses, the canary. This follows Microsoft's published defense-in-depth approach, which pairs Prompt Shields and spotlighting with deterministic blocking of markdown-image and link exfiltration ([MSRC, July 2025](https://www.microsoft.com/en-us/msrc/blog/2025/07/how-microsoft-defends-against-indirect-prompt-injection-attacks)).
- **Spotlighting by datamarking.** Retrieved text loses any marker characters and document tags, then has every space replaced by `ˆ` inside `<documents>` tags, and the system prompt says marked text is data. Hines et al. report that spotlighting cut attack success from over 50% to under 2% on their tasks ([arXiv 2403.14720](https://arxiv.org/abs/2403.14720)).
- **PIGuard without `trust_remote_code`.** Its card says to load it with remote code, so I read `modeling_piguard.py` at the pinned commit (a DeBERTa-v2 classifier with one linear layer on the [CLS] state) and reimplemented it in `detectors.py`. A download test checks its logits against the remote code at the same revision.
- **Sliding windows for long text.** Both detectors read 512 tokens, so a payload after a 250-word article would be truncated away. Long texts are scored in overlapping windows and take the maximum.
- **One detector, chosen on dev.** Each profile (PIGuard, deberta, both ORed) gets thresholds for 1% dev FPR, and the gateway runs the one with the best mean dev TPR, PIGuard alone. deberta stays in the benchmark as the baseline.
- **Presidio with the small spaCy model and my own checksum recognizers.** `en_core_web_sm` is 12 MB against about 400 MB for Presidio's default `en_core_web_lg`, and in this gateway it only feeds PERSON. The regex baseline and Presidio share one Luhn and one IBAN implementation, so the benchmark isolates what NER and context scoring add.

<details>
<summary>More design decisions: retries, circuit breaker, fallback, Prompt Shields, LiteLLM, redaction scope</summary>

- **stamina for retries, the harness for everything else.** Model calls go through llm-eval-harness (`FoundryClient`, `DollarCap`, `CachedClient`). Its `RetryingClient` sleeps with `time.sleep` in the worker thread, where the request deadline cannot cancel it. stamina retries with exponential backoff and jitter on `asyncio.sleep`, so the deadline wins. The OpenAI SDK's own retries are off (`max_retries=0`, the SDK default is 2 retries with a 600 s timeout per `openai/_constants.py`), and each call gets a timeout below the deadline. While the fallback could still run, the primary gets the remaining time minus min(12 s, half of it), so a hung primary still leaves the fallback its turn. A test checks this at the shipped timings on a virtual clock.
- **A hand-written async circuit breaker.** pybreaker 1.4.1 supports async only through Tornado, and purgatory's last release was November 2024. The breaker here is about 80 lines with a fake-clock test for each transition.
- **Retrieval-only fallback.** When both models fail, the customer still gets the top help-center articles with links. A 503 only happens when there is nothing to show.
- **Prompt Shields over REST, off by default.** It is called with httpx against `text:shieldPrompt?api-version=2024-09-01` ([quickstart](https://learn.microsoft.com/en-us/azure/ai-services/content-safety/quickstart-jailbreak)) only when `AZURE_CONTENT_SAFETY_ENDPOINT` and `AZURE_CONTENT_SAFETY_KEY` are set. Inputs over the service limits are split across calls instead of truncated, and results are cached. Foundry's own content filter is logged as its own layer (`azure_content_filter`). Any other provider policy refusal, a 400 with a code such as `invalid_prompt` or a policy message, ends the request as `provider_refusal`. Neither goes to the fallback model or counts as a breaker failure. A second model would give the attacker a second try, and refusals that opened the breaker would push benign traffic to the fallback. Other 4xx errors are configuration errors and still fail over.
- **No LiteLLM.** Versions 1.82.7 and 1.82.8 on PyPI carried a credential stealer on March 24, 2026 ([LiteLLM security update](https://docs.litellm.ai/blog/security-update-march-2026)). garak 0.17.0 declares LiteLLM as a hard dependency, so the scanner lives in its own uv project that overrides it out. A test fails if LiteLLM appears in the gateway's lockfile.
- **LOCATION and DATE_TIME are not redacted.** Country names and dates are what travel and dispute questions are about.
- **PIGuard's source.** It comes from the InjecGuard paper, which also introduced NotInject ([arXiv 2410.22770](https://arxiv.org/abs/2410.22770)).

</details>

## What didn't work

- **Two detectors ORed.** At the same 1% FPR it caught fewer dev direct injections than PIGuard alone (63.0% against 84.4%), since both thresholds rise to share the budget, and the test split agrees.
- **Vendor default thresholds.** ProtectAI's model at its 0.5 threshold flags about 1 in 20 Banking77 questions and more than 4 in 10 NotInject prompts, and tuning it to 1% dev FPR cut its recall on untransformed direct injections from 70.0% to 54.6%.
- **End-to-end attack success as a way to compare layers.** Every config, even the one without gateway guards, scored 0.0% on the 448 test attacks, because the public payloads are generic, none targets this gateway's canary or account context, and gpt-6-luna with a strict JSON reply format didn't follow them. The offline pipeline table carries the per-layer comparison instead.

<details>
<summary>Build and install problems</summary>

- **The first Docker build.** `python:3.11-slim` has no git, which uv needs to fetch llm-eval-harness at its pinned commit. The build stage now installs it.
- **Loading PIGuard's tokenizer through `AutoTokenizer` with default arguments.** The config's custom model type made transformers stop and ask, interactively, whether to run the repo's code. Passing `trust_remote_code=False` explicitly loads the stock DeBERTa-v2 tokenizer.
- **Installing garak next to the gateway.** It pins `datasets<4`, pulls LiteLLM and about 200 other packages, and resolved torch from PyPI with CUDA wheels until torch was named as a direct dependency (uv applies index sources only to direct dependencies). With LiteLLM overridden out, garak's encoding, latent-injection and web-injection probes failed to import, because `garak.payloads` needs `jsonschema` and only LiteLLM brought it in. The scanner now has its own project that lists `jsonschema` itself.

</details>

## Limitations

- **Pooled FPR hides per-set FPR.** The 1% target is on pooled dev benign prompts, most of which are Banking77. PIGuard still flags about 1 in 9 NotInject prompts on test, which are benign prompts built around words like "ignore". A support channel that gets many such questions would want its own dev set and threshold.
- **Homoglyphs beat both detectors at the tuned thresholds.** Cyrillic look-alike letters drop both models to near zero recall, and NFKC does not fold them. A confusables map (Unicode TR39) before detection is the obvious next step and is not built.
- **Static suite.** Everything here is a fixed set of public payloads plus mechanical transforms. An attacker who can query the gateway and adapt will do better (Nasr et al., [arXiv 2510.09023](https://arxiv.org/abs/2510.09023)). That's why detector verdicts are hidden from clients and why garak gets its own table.
- **Code-judged ASR is a lower bound.** A goal hijack that leaks nothing ("say something rude about a newspaper") does not count as a success. JailbreakBench goals need a judge to score, so for them only blocks and leaks are measured.
- **In-memory limits.** slowapi's store, the token budget and the circuit breakers are per process. Several replicas would need a shared store such as Redis.

<details>
<summary>More limitations</summary>

- **Wide intervals on indirect injection.** The 79 test payloads come from 16 LLMail-Inject teams, and payloads from one team are alike, so the intervals are clustered by team and wide.
- **Contamination.** PIGuard was trained on the deepset train split, where most of this suite's deepset rows come from, so a separate row reports the test-split rows alone ([DATA_SOURCES.md](DATA_SOURCES.md#training-data-overlap)).
- **Encoded text gets decoded and repeated, and encoded benign input gets refused.** garak's hex and base64 probes each succeeded on 1 of 40 prompts (an earlier run of the same probes, before the provider-refusal fix, had 4 of 40 on hex, so these counts move between runs). In every hit, luna decoded the string, an offensive term from garak's payload list, and repeated it in its answer. No hit leaked the canary, PII or a link, since the output rules look for leaks, not offensive text. A moderation check on the reply would close this. Neither injection detector reads hex, and PIGuard's base64 flags come from the format: at the tuned threshold it flags all 450 base64 benign prompts and 85% of leetspeak ones, so a customer who pastes base64 or writes in leetspeak gets the refusal.
- **Detection runs on redacted text.** Presidio redacts the prompt before the injection detector scores it, and its false PERSON hits on encoded blobs can pull a score under the threshold. So the pipeline blocks 112 of 130 untransformed direct injections where the detector alone flags 113, and 202 of 265 against 210 with the transformed ones.
- **One model call at a time.** The live server sends both model slots through one serialized client, because the harness `DollarCap` isn't thread-safe. Concurrent requests queue. A request cancelled by its deadline releases the lock while its worker thread keeps running, so timed-out calls can pile up inside `DollarCap` and the thread pool.
- **Other canary encodings.** The canary check catches plain, spaced, reversed and base64 forms. Hex, ROT13, a translation or a paraphrase of the marker gets through.
- **Bare domains.** A domain with no scheme or `www.`, like `evil.example/path`, isn't treated as a link. GitHub-flavored Markdown doesn't autolink it, but a client that does would show a live link.
- **One bucket behind a proxy.** Without `GATEWAY_API_KEYS`, rate limits and token budgets are keyed on the client IP. That mode is for development. Behind a reverse proxy every user has the proxy's IP and shares one bucket, so a deployment needs configured keys.
- **`blocked_by` is an oracle.** The per-layer trace is hidden, but the response still names the blocking layer. `output_canary` tells an attacker the leak was caught and a different encoding might not be.
- **Synthetic domain.** The help center, questions and account context are synthetic. Banking77 is real customer wording but short and clean.
- **Label noise in the PII sets.** gretel's labels came from a NER library plus an LLM judge, which lowers measured precision for any system ([DATA_SOURCES.md](DATA_SOURCES.md#datasets)).
- **CPU latency on one small machine.** Latency was measured on an otherwise idle Azure D4s v6 (4 vCPU on 2 physical cores, PyTorch at 2 threads). A busy machine is much slower: an earlier run on a shared container measured a document-detector p95 of 24 s against 0.8 s here.
- **Replay is close, not exact.** `make eval-e2e` replays the committed cache, but the harness caches only successful replies. The live run used Foundry's default content filter (`Microsoft.DefaultV2`), because Azure refused an annotate-only policy without an approved exception, and it blocked 4 of the 598 requests in the config without gateway guards (logged as `azure_content_filter`). Another 20 requests (9, 10 and 1 across the three configs) got a 400 from luna with code `cyber_policy` or `bio_policy`, which the gateway ends as `provider_refusal` with the fixed refusal instead of sending them to gpt-5-mini. An earlier run of the gateway failed those over to gpt-5-mini, which answered them. The filtered and refused requests come out differently on replay, replayed calls cost $0, and which prompts luna refuses varies a little from run to run. `make demo` renders from the committed live records, so the README numbers don't depend on replay.
- **No human labels.** Nothing in this repo was labeled or reviewed by a person.
- **Prompt Shields was not run.** The Prompt Shields client is tested only against a mock transport.

</details>

## Cost

Offline everything costs $0. The live parts use `gpt-6-luna` ($0.10 per million input tokens, $0.50 per million output) with `gpt-5-mini` as the fallback.

| Run | Command | Requests (upper bound) | Estimate | Hard cap |
|---|---|---|---|---|
| End-to-end, 3 configs, 448 test attacks and 150 benign questions | `make eval-e2e-live` | about 1,800 | about $0.40 | $2.00 (`DollarCap`) |
| garak, 12 probes at a 40-prompt cap | `make garak` against a live gateway | about 500 | about $0.10 | $1.00 (`GATEWAY_DOLLAR_CAP_USD`) |

The estimates assume about 1,500 input and 120 output tokens per model call and ignore the prompt-cache discount. The Cost column in the end-to-end table prices each record's tokens at list price, also with no prompt-cache discount. Requests the gateway blocks before the model cost nothing.

## How I built this

The code was written with Claude Code as a pair programmer, under my direction and review.

## License

MIT. Copyright (c) 2026 Richard K. Dataset licenses are listed in `DATA_SOURCES.md`.
