# SIEM Triage Assistant

An LLM-powered analyst decision support tool built on the Anthropic Claude API.
Designed to augment — not replace — SIEM alert triage by providing structured
reasoning about verdict accuracy, blast radius, and recommended action.

---

## Overview

SIEMs are excellent at the structured part of security operations: correlating
events, firing rules, and surfacing alerts. What they do not do is help an
analyst decide what to do next. Every alert still lands on a human who must
answer three questions:

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
  1     v1_zeroshot_baseline           2/2        ████████████████████ 100%  ← best
  2     v4_oneshot_fp                  5/5        ████████████████████ 100%
  3     v5_fewshot_tp_heavy            5/5        ████████████████████ 100%
  4     v6_fewshot_balanced            5/5        ████████████████████ 100%
  5     v8_role_enriched               5/5        ████████████████████ 100%
  6     v2_zeroshot_structured         4/5        ████████████████░░░░ 80%
  7     v10_cot_structured             4/5        ████████████████░░░░ 80%
  8     v7_role_basic                  3/4        ███████████████░░░░░ 75%
  9     v9_cot_freeform                2/3        █████████████░░░░░░░ 67%
  10    v3_oneshot_tp                  0/0        ░░░░░░░░░░░░░░░░░░░░ 0%
════════════════════════════════════════════════════════════════════════
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

<!-- PLACEHOLDER: Document at least one failure per low-scoring variant.
     For each failure note:
     - Which prompt variant
     - Which alert
     - What Claude got wrong
     - Why you believe it failed (reasoning gap, bias, missing context)

     Example format:
     **v3_oneshot_tp × DD-SIG-2025-0501**
     Claude returned TRUE_POSITIVE with HIGH confidence on the VP of Sales
     traveling to London. The single TP example primed the model to pattern-match
     on the geo anomaly without weighing the travel notice or recognized device.
-->

---

## Key Findings

<!-- PLACEHOLDER: Write 4-5 specific, data-driven findings after running
     the evaluation. These should be falsifiable statements supported by
     your scorecard. Avoid vague conclusions.

     Bad:  "Claude performed well on most prompts."
     Good: "Role-enriched prompting (v8) reduced false positive rate from
            X% to Y% compared to the zero-shot baseline (v1), driven primarily
            by the VPN topology context resolving alert DD-SIG-2025-0534."

     Suggested structure:
     1. Which variant performed best overall and why
     2. Where zero-shot failed most visibly
     3. What the one-shot bias experiment revealed
     4. How confidence calibration varied across techniques
     5. The most surprising or counterintuitive result
-->

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

## What I Would Do Next

<!-- PLACEHOLDER: 3-5 bullet points on Phase 2 ideas. Shows an experimenter
     mindset — that this project is a starting point, not a finished product.

     Ideas to consider:
     - Test with real Datadog signal exports (anonymized)
     - Add a retrieval layer: pull live travel notices and VPN IP lists at runtime
     - Evaluate claude-sonnet vs claude-haiku on accuracy-to-cost tradeoff
     - Build a feedback loop: analyst overrides feed back into few-shot examples
     - Extend to additional rule types: DLP, privilege escalation, lateral movement
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