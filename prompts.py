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

"""