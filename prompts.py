"""
prompts.py — SIEM Triage Assistant

10 prompt variants across 5 techniques (2 per technique),
testing how different prompting approaches affect the quality
of analyst triage decisions.

Prompt techniques used:
Zero-shot — no examples, tests schema impact (v1, v2)
One-shot — single example, tests example bias direction (v3, v4)
Few-shot — multiple examples, tests balance vs bias (v5, v6)
Role-based — persona, tests depth of context (v7, v8)
Chain-of-thought — step-by-step reasoning, tests schema impact (v9, v10)

Each prompt expects a Datadog security signal as a JSON-formatted
string appended to the prompt at runtime by evaluate.py.
 
Output schema (all structured variants target this JSON format):
{
    "verdict":              "TRUE_POSITIVE", "FALSE_POSITIVE", or "NEEDS_INVESTIGATION",
    "confidence":          "HIGH", "MEDIUM", or "LOW",
    "blast_radius":        "Description of affected users, systems, and lateral scope",
    "recommended_action":  "close_as_fp", "investigate_independently", "suspend_session",
                           "escalate_tier2", "legal_hold", or "monitor_and_watch",
    "action_rationale":    "One sentence explaining why this action, not another",
    "reasoning":           "Evidence-based logic that drove the verdict",
    "what_would_change_this": "What additional context would flip or strengthen the verdict"   
}
"""