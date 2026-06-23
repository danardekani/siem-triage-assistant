import json
import os
import time

import anthropic
from dotenv import load_dotenv

from alerts import ALERTS
from prompts import PROMPTS

## Configuration
MODEL          = "claude-haiku-4-5-20251001"
MAX_TOKENS     = 1024
OUTPUT_FILE    = "outputs.json"
SLEEP_BETWEEN  = 0.5   # seconds between API calls — avoids rate limits
MAX_RETRIES    = 3     # retry attempts on 500 errors before giving up
RETRY_BASE     = 5     # base seconds for exponential backoff (5, 10, 20)

# Variants that return free-form text (no JSON schema enforced).
# Verdict extraction is attempted via keyword matching, not parsing.
FREEFORM_VARIANTS = {"v1_zeroshot_baseline", "v9_cot_freeform"}

## Helpers

def call_with_retry(client, **kwargs):
    """
    Calls the Anthropic API with exponential backoff retry logic.
    Retries on 500 (internal server error) and 529 (overloaded) errors.
    Raises the final exception if all retries are exhausted.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return client.messages.create(**kwargs)
        except anthropic.InternalServerError as e:
            if attempt == MAX_RETRIES:
                raise
            wait = RETRY_BASE * (2 ** (attempt - 1))   # 5s, 10s, 20s
            print(
                f"\n  ⚠ 500 error (attempt {attempt}/{MAX_RETRIES}) — "
                f"retrying in {wait}s..."
            )
            time.sleep(wait)
        except anthropic.APIStatusError as e:
            if e.status_code == 529:
                if attempt == MAX_RETRIES:
                    raise
                wait = RETRY_BASE * (2 ** (attempt - 1))
                print(
                    f"\n  ⚠ 529 overloaded (attempt {attempt}/{MAX_RETRIES}) — "
                    f"retrying in {wait}s..."
                )
                time.sleep(wait)
            else:
                raise   # don't retry other errors (404, 401, etc.)


def extract_verdict_from_json(response_text):
    """
    Attempt to parse Claude's response as JSON and extract the verdict.
    Returns (parsed_dict, verdict_str) or (None, None) on failure.
    """
    try:
        # Strip markdown code fences if Claude added them despite instructions
        cleaned = response_text.strip()
        if cleaned.startswith("```"):
            cleaned = cleaned.split("```")[1]
            if cleaned.startswith("json"):
                cleaned = cleaned[4:]
        parsed = json.loads(cleaned.strip())
        verdict = parsed.get("verdict", None)
        return parsed, verdict
    except (json.JSONDecodeError, IndexError):
        return None, None


def infer_verdict_from_text(response_text):
    """
    Best-effort verdict extraction from free-form text output.
    Looks for verdict keywords in the response. Labeled as
    'inferred' in output — not treated as parsed structured data.
    """
    upper = response_text.upper()
    if "TRUE_POSITIVE" in upper or "TRUE POSITIVE" in upper:
        return "TRUE_POSITIVE"
    if "FALSE_POSITIVE" in upper or "FALSE POSITIVE" in upper:
        return "FALSE_POSITIVE"
    if "NEEDS_INVESTIGATION" in upper or "NEEDS INVESTIGATION" in upper:
        return "NEEDS_INVESTIGATION"
    return None


def verdict_is_correct(extracted, ground_truth):
    """
    Returns True if extracted verdict matches ground truth.
    Returns None if verdict could not be extracted.
    """
    if extracted is None:
        return None
    return extracted == ground_truth


def print_progress(current, total, prompt_name, alert_id):
    bar_len  = 30
    filled   = int(bar_len * current / total)
    bar      = "█" * filled + "░" * (bar_len - filled)
    pct      = int(100 * current / total)
    print(f"  [{bar}] {pct:>3}%  {prompt_name:<30} × {alert_id}", flush=True)


def print_leaderboard(results):
    """
    Calculate and print verdict accuracy per prompt variant,
    ranked from highest to lowest accuracy.
    """
    from collections import defaultdict

    stats = defaultdict(lambda: {"correct": 0, "scoreable": 0, "total": 0})

    for r in results:
        v = r["prompt_variant"]
        stats[v]["total"] += 1
        if r["verdict_correct"] is not None:
            stats[v]["scoreable"] += 1
            if r["verdict_correct"]:
                stats[v]["correct"] += 1

    # Build ranked list
    ranked = []
    for variant, s in stats.items():
        accuracy = (s["correct"] / s["scoreable"] * 100) if s["scoreable"] > 0 else 0
        ranked.append((variant, s["correct"], s["scoreable"], s["total"], accuracy))

    ranked.sort(key=lambda x: x[4], reverse=True)

    print("\n" + "═" * 72)
    print("  VERDICT ACCURACY LEADERBOARD")
    print("═" * 72)
    print(f"  {'Rank':<5} {'Variant':<30} {'Correct':<10} {'Accuracy'}")
    print("─" * 72)

    for i, (variant, correct, scoreable, total, accuracy) in enumerate(ranked, 1):
        bar    = "█" * int(accuracy / 5) + "░" * (20 - int(accuracy / 5))
        marker = "  ← best" if i == 1 else ""
        print(
            f"  {i:<5} {variant:<30} {correct}/{scoreable:<7}  "
            f"{bar} {accuracy:.0f}%{marker}"
        )

    print("═" * 72)
    print(f"\n  Total API calls: {len(results)}")
    unscored = sum(1 for r in results if r["verdict_correct"] is None)
    if unscored:
        print(f"  Unscored outputs (parse failure): {unscored}")
    print()


## Main

def main():
    # Load API key from .env
    load_dotenv()
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise EnvironmentError(
            "ANTHROPIC_API_KEY not found. "
            "Add it to a .env file in this directory."
        )

    client  = anthropic.Anthropic(api_key=api_key)
    results = []
    total   = len(PROMPTS) * len(ALERTS)
    current = 0

    print(f"\n  SIEM Triage Assistant — Evaluation Run")
    print(f"  Model:    {MODEL}")
    print(f"  Prompts:  {len(PROMPTS)}")
    print(f"  Alerts:   {len(ALERTS)}")
    print(f"  Total calls: {total}\n")

    for prompt_name, prompt_text in PROMPTS.items():
        for alert in ALERTS:

            current += 1
            print_progress(current, total, prompt_name, alert["alert_id"])

            # Build message content — prompt + alert JSON
            alert_payload = {
                k: v for k, v in alert.items()
                if k != "_ground_truth"   # never send ground truth to the model
            }
            message_content = prompt_text + json.dumps(alert_payload, indent=2)
            ground_truth    = alert["_ground_truth"]["verdict"]
            is_freeform     = prompt_name in FREEFORM_VARIANTS

            ## API call
            try:
                response = call_with_retry(
                    client,
                    model=MODEL,
                    max_tokens=MAX_TOKENS,
                    messages=[
                        {"role": "user", "content": message_content}
                    ],
                )
                response_text = response.content[0].text
                input_tokens  = response.usage.input_tokens
                output_tokens = response.usage.output_tokens

            except anthropic.APIError as e:
                print(f"\n  ⚠ API error on {prompt_name} × {alert['alert_id']}: {e}")
                results.append({
                    "prompt_variant":    prompt_name,
                    "alert_id":          alert["alert_id"],
                    "rule_name":         alert["rule_name"],
                    "ground_truth":      ground_truth,
                    "claude_response":   None,
                    "parsed_output":     None,
                    "extracted_verdict": None,
                    "verdict_source":    None,
                    "verdict_correct":   None,
                    "is_freeform":       is_freeform,
                    "input_tokens":      None,
                    "output_tokens":     None,
                    "error":             str(e),
                })
                continue

            ## Extract verdict
            if is_freeform:
                parsed_output     = None
                extracted_verdict = infer_verdict_from_text(response_text)
                verdict_source    = "inferred"
            else:
                parsed_output, extracted_verdict = extract_verdict_from_json(response_text)
                verdict_source = "parsed" if parsed_output else "parse_failed"

            correct = verdict_is_correct(extracted_verdict, ground_truth)

            results.append({
                "prompt_variant":    prompt_name,
                "alert_id":          alert["alert_id"],
                "rule_name":         alert["rule_name"],
                "ground_truth":      ground_truth,
                "claude_response":   response_text,
                "parsed_output":     parsed_output,
                "extracted_verdict": extracted_verdict,
                "verdict_source":    verdict_source,
                "verdict_correct":   correct,
                "is_freeform":       is_freeform,
                "input_tokens":      input_tokens,
                "output_tokens":     output_tokens,
                "error":             None,
            })

            time.sleep(SLEEP_BETWEEN)

    ## Save results
    print(f"\n  Saving results to {OUTPUT_FILE}...")
    with open(OUTPUT_FILE, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  Done. {len(results)} outputs saved.\n")

    ## Leaderboard
    print_leaderboard(results)


if __name__ == "__main__":
    main()