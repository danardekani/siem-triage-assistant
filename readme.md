# SIEM Triage Assistant

An LLM-powered analyst decision support tool built on the Anthropic Claude API.
Designed to augment, but not replace SIEM alert triage by providing structured
reasoning about verdict accuracy, blast radius, and recommended action.

---

## Overview

SIEMs are excellent at the structured part of security operations: correlating
events, firing rules, and surfacing alerts. What they do not do is help an
analyst decide what to do next. Every alert still requires human in the loop intervention. 
A human must answer three questions:

1. Is this a true positive or a false positive?
2. What is the blast radius — who and what is affected?
3. What should happen next — dismiss, investigate, escalate, or contain?

This project builds and evaluates a Claude-powered triage assistant that sits
downstream of the SIEM and helps answer those questions. The SIEM does its job.
Claude does the reasoning the SIEM was never designed to do.

---

## System Architecture

```
┌─────────────────────┐
│   Datadog SIEM      │  Fires rule, generates structured signal
└────────┬────────────┘
         │  Security signal (JSON)
         ▼
┌─────────────────────┐
│   evaluate.py       │  Injects signal into prompt template
└────────┬────────────┘
         │  Prompt + alert payload
         ▼
┌─────────────────────┐
│   Claude API        │  Reasons about evidence, returns triage decision
│   (Haiku 3.5)       │
└────────┬────────────┘
         │  Structured JSON decision package
         ▼
┌─────────────────────┐
│   Analyst           │  Reviews verdict, acts on recommendation
└─────────────────────┘
```

Claude receives the structured SIEM output and returns a triage decision package
containing a verdict, confidence level, blast radius assessment, recommended
action, and the reasoning behind the call.

---

## Use Case

**Security alert triage — impossible travel and identity-based threats**

The evaluation focuses on the alert types most commonly triaged in enterprise
SOC environments: impossible travel geo-anomalies, credential-based attacks,
and insider threat signals. These were chosen because:

- They represent the highest daily volume in most SIEM deployments
- Business context (travel notices, VPN topology, user status) is frequently
  the difference between a true positive and a false positive
- That business context is exactly what SIEMs lack and Claude can reason about

---

## Alert Inputs

Five structured test alerts modeled after Datadog Security Signal output format.
Each was chosen to stress-test a specific reasoning failure mode.

| Alert ID | Rule | Ground Truth | What it tests |
|---|---|---|---|
| DD-SIG-2025-0471 | Impossible Travel | TRUE_POSITIVE | Baseline — clear-cut TP, no ambiguity |
| DD-SIG-2025-0488 | Brute Force → Auth Success | NEEDS_INVESTIGATION | Ambiguity — recognized device and prior cleared pattern |
| DD-SIG-2025-0501 | Impossible Travel | FALSE_POSITIVE | Business context FP — travel notice on file |
| DD-SIG-2025-0519 | Large Volume Download Off-Hours | TRUE_POSITIVE | Insider threat — weak signals that compound |
| DD-SIG-2025-0534 | Impossible Travel | FALSE_POSITIVE | Technical FP — corporate VPN exit node |

Ground truth verdicts were set by the analyst based on real SOC experience,
not algorithmic output. This domain expertise is what makes the evaluation
credible — the evaluator knows what correct looks like.

**Note on alert 5:** The most technically sophisticated test case. The geo
anomaly is caused by a corporate Mullvad VPN exit node routing auth traffic
through Amsterdam. A model reading only `geo_country` calls this a true
positive. A model reasoning about `isp`, `ip_type`, and `known_corporate_vpn`
correctly identifies it as a false positive.

---

## Prompt Techniques Tested

Ten variants across five techniques — two per technique — where each pair
isolates a single variable.

### 1. Zero-shot
No examples, no persona, no reasoning instruction. Tests unguided output quality.

| Variant | Description |
|---|---|
| `v1_zeroshot_baseline` | No schema — Claude formats output freely. True floor. |
| `v2_zeroshot_structured` | Adds output schema. Tests what format constraint alone contributes. |

### 2. One-shot
Exactly one example before the alert. Tests whether a single example creates
directional bias in the model's verdicts.

| Variant | Description |
|---|---|
| `v3_oneshot_tp` | Single true positive example. Expected to bias toward overcalling TPs. |
| `v4_oneshot_fp` | Single false positive example. Expected to bias toward undercalling TPs. |

### 3. Few-shot
Multiple examples before the alert. Tests whether example balance affects
verdict calibration.

| Variant | Description |
|---|---|
| `v5_fewshot_tp_heavy` | 2 TP + 1 FP examples. Slightly biased toward TP. |
| `v6_fewshot_balanced` | 2 TP + 2 FP examples. Perfectly balanced. |

### 4. Role-based
Analyst persona with domain expertise. Tests whether depth of context
improves false positive detection.

| Variant | Description |
|---|---|
| `v7_role_basic` | Senior Tier 2 SOC Analyst persona only. |
| `v8_role_enriched` | Same persona plus institutional context: VPN topology, gateway routing, travel notice policy, insider risk indicators. |

### 5. Chain-of-thought
Explicit step-by-step reasoning before verdict. Tests whether structured
reasoning reduces wrong answers and whether a schema improves output
consistency without sacrificing reasoning quality.

| Variant | Description |
|---|---|
| `v9_cot_freeform` | 8-step reasoning framework, free-form output. |
| `v10_cot_structured` | Same reasoning framework plus output schema. |

---

## Evaluation Framework

Each structured output was scored against five criteria on a 1–5 scale.
Free-form outputs (v1, v9) were scored on verdict accuracy and reasoning
validity only.

| Criterion | What a 5 looks like | What a 1 looks like |
|---|---|---|
| **Verdict accuracy** | Correct TP / FP / NI call | Wrong call with no caveats |
| **Confidence calibration** | HIGH only when evidence is strong | HIGH confidence on ambiguous alerts |
| **Reasoning validity** | Logic follows evidence step by step | Correct verdict reached via flawed logic |
| **Blast radius assessment** | Correctly scopes affected users and systems | Misses lateral movement risk or over-scopes |
| **Actionability** | Analyst can act without additional research | Vague or unexecutable recommendation |

**On confidence calibration:** This is the most sophisticated criterion in the
framework. It rewards Claude for expressing uncertainty when the evidence is
weak — something junior analysts frequently get wrong too. A high-confidence
wrong verdict is a more serious failure than a low-confidence wrong verdict.

---

## Results

> **Note:** Run `python evaluate.py` to generate results. Replace the
> placeholders below with your actual output.

### Verdict Accuracy Leaderboard

```
════════════════════════════════════════════════════════════════════════
  VERDICT ACCURACY LEADERBOARD
════════════════════════════════════════════════════════════════════════
  Rank  Variant                        Correct    Accuracy
────────────────────────────────────────────────────────────────────────
  1     v4_oneshot_fp                  5/5        ████████████████████ 100%  ← best
  2     v5_fewshot_tp_heavy            5/5        ████████████████████ 100%
  3     v6_fewshot_balanced            5/5        ████████████████████ 100%
  4     v8_role_enriched               5/5        ████████████████████ 100%
  5     v2_zeroshot_structured         4/5        ████████████████░░░░ 80%
  6     v7_role_basic                  4/5        ████████████████░░░░ 80%
  7     v10_cot_structured             4/5        ████████████████░░░░ 80%
  8     v1_zeroshot_baseline           2/3        █████████████░░░░░░░ 67%
  9     v9_cot_freeform                2/4        ██████████░░░░░░░░░░ 50%
  10    v3_oneshot_tp                  0/0        ░░░░░░░░░░░░░░░░░░░░ 0%
════════════════════════════════════════════════════════════════════════

  Total API calls: 50
  Unscored outputs (parse failure): 8
```

### Scorecard

<!-- PLACEHOLDER: Insert your completed scorecard table here.
     Rows = prompt variants, columns = scoring criteria.
     Template:

| Variant | Verdict Accuracy | Confidence Calibration | Reasoning Validity | Blast Radius | Actionability | Total |
|---|---|---|---|---|---|---|
| v1_zeroshot_baseline     | /5 | /5 | /5 | /5 | /5 | /25 |
| v2_zeroshot_structured   | /5 | /5 | /5 | /5 | /5 | /25 |
| v3_oneshot_tp            | /5 | /5 | /5 | /5 | /5 | /25 |
| v4_oneshot_fp            | /5 | /5 | /5 | /5 | /5 | /25 |
| v5_fewshot_tp_heavy      | /5 | /5 | /5 | /5 | /5 | /25 |
| v6_fewshot_balanced      | /5 | /5 | /5 | /5 | /5 | /25 |
| v7_role_basic            | /5 | /5 | /5 | /5 | /5 | /25 |
| v8_role_enriched         | /5 | /5 | /5 | /5 | /5 | /25 |
| v9_cot_freeform          | /5 | /5 | /5 | /5 | /5 | /25 |
| v10_cot_structured       | /5 | /5 | /5 | /5 | /5 | /25 |
-->

### Notable Failures

**v1_zeroshot_baseline and v9_cot_freeform — partial parse failures**
 
Both variants intentionally use no output schema. The script uses keyword
matching to infer verdicts from free-form text. On 3 combined responses,
Claude hedged in ways that produced no clean keyword hit — phrases like
"this alert warrants closer examination" rather than a discrete verdict.
These responses could not be scored programmatically.

**v3_oneshot_tp — all 5 responses unparseable (0/0 scored)**
 
Claude produced accurate, well-reasoned triage decisions across all 5 alerts
but returned markdown reports instead of JSON on every run. The single TP
example's rich narrative format overrode the explicit output schema instruction.
This is a format dominance failure: when example style conflicts with schema
instructions, Claude favors the implicit signal from the example over the
explicit format constraint that follows it.
 
Sample response structure Claude returned instead of JSON:
 
```
# SECURITY ALERT TRIAGE REPORT
## TRIAGE DECISION
**PRIORITY: HIGH**
**RECOMMENDATION: ESCALATE & INVESTIGATE IMMEDIATELY**
## RISK ASSESSMENT
...
```
 
The reasoning itself was correct. The format made it completely unparseable.

---

## Key Findings

**1. Context beats technique**
 
Four variants achieved 100% verdict accuracy, spanning three different
techniques: one-shot (v4), few-shot (v5, v6), and role-based (v8). The
common denominator across all four is not which technique was used — it was contenxt.
Each prompt variant gave Claude some form of context beyond a bare instruction. 
The three variants that failed to reach 100% (v2, v7, v10) all lacked either examples
or enriched institutional knowledge.

**2. Example selection in one-shot prompting determines whether the prompt
works at all**
 
v3 and v4 are identical in every respect: same role context, same output
schema, same instruction wording, same 5 alerts. The only variable is which
single example was provided. v3 used a true positive example and produced
0 scoreable results. The format collapsed entirely across all 5 runs. v4 used
a false positive example and achieved 5/5 correct verdicts, ranking first
in the evaluation. This is the starkest finding in the project: in one-shot
prompting, example selection is critical — is not a minor tuning decision. 
It determines whether the prompt functions at all.

**3. A single FP example taught better reasoning than a TP example**
 
The intuitive expectation was that v4's FP example would bias Claude toward
undercalling threats — particularly on the two clear true positives. The
opposite happened. The FP example taught Claude to look for mitigating
evidence before rendering a verdict. That reasoning discipline carried over
to the TP alerts: when Claude applied the same careful scrutiny to alert 1
(Lagos, no travel notice, unrecognized device, no MFA), the evidence for a
true positive was overwhelming and it called it correctly. One well-chosen
false positive example improved reasoning quality across all verdict types.

**4. Schema-free variants are consistently the weakest performers**
 
v1 and v9 ranked 8th and 9th respectively. Without a structured output
constraint, Claude produced narrative responses that did not map
cleanly to triage decisions. This held true regardless of how
good the reasoning was — v9's chain-of-thought responses frequently
contained correct analysis but no parseable verdict. Format constraints
have proved to be a functional requirement this project, and likely, 
for any production triage tool.

**5. Institutional context closed the FP gap that role alone
could not**
 
v7 (role only) scored 80%. v8 (role plus institutional context) scored 100%.
The role description is identical between them. The only addition in v8 is
organizational knowledge the SIEM does not have access to: VPN exit node
topology, gateway routing behavior, travel notice policy, and insider risk
indicators. That context is what correctly resolved the two false positive
alerts. The traveling VP and the VPN exit node is what v7 missed. The SIEM
fired correctly on the geo signal. Claude with institutional context understood
why the signal did not mean what it appeared to mean.

---

## Production Recommendation

<!-- PLACEHOLDER: Write your production recommendation after reviewing results.
     This is the section that demonstrates you think beyond the experiment.
     A hiring manager reading this should see someone who has already thought
     about real-world deployment.

     Address:
     - Which prompt strategy you would deploy and why
     - What the accuracy-to-cost tradeoff looks like (token counts are in outputs.json)
     - Whether you would use one strategy for all alerts or vary by severity or rule type
     - What rule tuning you would recommend based on FP patterns observed

     Example opening:
     "Based on evaluation results, v8_role_enriched is the recommended production
     prompt for impossible travel alerts. While v10_cot_structured achieved
     comparable accuracy, the additional token cost of chain-of-thought reasoning
     is not justified for alerts where institutional context alone resolves the
     verdict..."
-->

---

### Annual Cost Projection
 
Token averages derived from real v8_role_enriched API runs (n=2):
~1,230 input tokens and ~483 output tokens per call.
 
**Pricing: Haiku 4.5 at $1.00 input / $5.00 output per million tokens**
 
| Scenario | Alerts/Day | Alerts/Year | Standard | Batch API (-50%) | Batch + Cache (-52%) |
|---|---|---|---|---|---|
| Small SOC | 10 | 3,650 | $13.31 | $6.65 | $6.33 |
| Mid-size SOC | 50 | 18,250 | $66.53 | $33.27 | $31.65 |
| Large SOC | 200 | 73,000 | $266.12 | $133.06 | $126.59 |
| Enterprise | 1,000 | 365,000 | $1,330.61 | $665.30 | $632.97 |
 
At $0.0037 per call, an enterprise SOC processing 1,000 identity alerts per day
spends under $1,331 per year at standard rates — less than 2% of a single Tier 1
analyst salary. Cost is not a deployment barrier at any scale.
 
**Batch API tradeoff:** The 50% Batch API discount processes requests
asynchronously within 24 hours. For HIGH severity alerts this latency is
unacceptable — use the standard synchronous API. For MEDIUM and below, batch
processing is appropriate and halves the cost.
 
**Model upgrade path:** Sonnet 4.6 costs 3x more than Haiku 4.5 ($3/$15 vs
$1/$5 per million tokens). At mid-size SOC volume that difference is only
$133/year — meaning model quality, not cost, should drive any decision to
upgrade tiers.

--- 

## What I Would Do Next

- **Build the webhook integration.** The alert inputs in this project mirror
  the JSON structure of real Datadog Security Signals. The natural next step
  is a FastAPI endpoint that receives live signals via Datadog webhook,
  passes them to Claude using the v8 prompt, and writes the triage decision
  back to the signal as a Datadog comment — closing the loop from detection
  to decision without analyst intervention on clear-cut cases.
- **Test with anonymized real signal exports.** The mock alerts in this
  project were constructed to test specific failure modes. Real Datadog
  signals contain noise, missing fields, and edge cases that synthetic data
  cannot replicate. Running this evaluation against anonymized production
  signals would reveal failure modes that controlled test inputs cannot surface.
- **Evaluate claude-sonnet-4-6 against claude-haiku-4-5 on accuracy and cost.**
  Haiku was chosen for this evaluation for cost efficiency. For high-severity
  alerts — particularly insider threat signals like DD-SIG-2025-0519 — the
  reasoning depth of Sonnet may justify the higher token cost. A comparative
  evaluation across model tiers would produce a tiered deployment recommendation:
  Haiku for routine alerts, Sonnet for critical severity.
- **Build a feedback loop from analyst overrides.** When an analyst overrides
  Claude's verdict, that override is a labeled training signal. A production
  system could capture those overrides and automatically promote them as new
  few-shot examples in the prompt, progressively improving accuracy without
  manual prompt engineering.

- **Integrate SOC playbooks into the triage decision output.** Currently
  Claude returns a verdict and a recommended action. The natural extension
  is to attach the relevant response playbook directly to that output. Given
  a TRUE_POSITIVE verdict on an impossible travel alert, Claude would return
  not just "suspend session" but the full procedural context an analyst needs
  to execute: what happened, where things currently stand, and the step-by-step
  playbook to respond. This compresses the time between detection and containment
  by eliminating the analyst's need to locate and cross-reference a separate
  runbook — the procedure arrives with the verdict.
-->

---

## How to Run

```bash
git clone https://github.com/your-username/siem-triage-assistant
cd siem-triage-assistant

pip install anthropic python-dotenv

# Add your Anthropic API key
echo "ANTHROPIC_API_KEY=your-key-here" > .env

python evaluate.py
```

Results are saved to `outputs.json`. The leaderboard prints to the terminal
on completion.

---

## Repository Structure

```
siem-triage-assistant/
├── README.md          # This file
├── evaluate.py        # Main script — runs all 50 prompt/alert combinations
├── prompts.py         # 10 prompt variants across 5 techniques
├── alerts.py          # 5 structured test alert inputs with ground truth
├── outputs.json       # Raw Claude responses (generated on first run)
├── scorecard.csv      # Evaluation scores (completed manually after run)
├── .env               # API key — never committed to GitHub
└── .gitignore         # Excludes .env
```

---

## Technologies

- [Anthropic Claude API](https://docs.anthropic.com) — `claude-haiku-4-5-20251001`
- Python 3.x
- `anthropic` SDK
- `python-dotenv`

---

*Built as a prompt engineering portfolio project. Use case domain informed by
5+ years of enterprise SOC operations experience.*