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
    "action_rationale":    "One entence explaining why this action, not another",
    "reasoning":           "Evidence-based logic that drove the verdict",
    "what_would_change_this": "What additional context would flip or strengthen the verdict"   
}

NOTE on recommended_action values:
- investigate_independently: Review gateway logs, VPN context, and prior sessions
  BEFORE engaging the user. SSO sign-ins route through internet gateways that may
  not reflect the user's physical location — independent verification first.
- suspend_session: Revoke active session immediately. Used only for high-confidence TPs.
- close_as_fp: Close and document. Used only for high-confidence FPs.
- escalate_tier2: Hand off for deeper investigation. For NEEDS_INVESTIGATION verdicts.
- legal_hold: Preserve artifacts and notify legal. For insider threat scenarios.
- monitor_and_watch: Flag for observation without action. For low-confidence signals.
"""

# ─────────────────────────────────────────────────────────────
# Fixed contraints — must be obeyed by all variants.
# ─────────────────────────────────────────────────────────────

ROLE = """You are a Senior Tier 2 SOC Analyst with 8 years of experience triaging
security alerts in enterprise environments. You specialize in identity-based
threats, impossible travel analysis, and insider risk detection.
 
You approach every alert with skepticism in both directions — you do not
assume a true positive without clear evidence, and you do not dismiss alerts
without accounting for the specific context provided.
 
You know that SSO sign-ins are often routed through corporate internet gateways
or VPN exit nodes that may not reflect the user's physical location. You always
check for this before rendering a verdict on geo-anomaly alerts.
 
Your triage decisions are precise, evidence-based, and actionable."""
 
OUTPUT_SCHEMA = """
Respond ONLY with a valid JSON object using exactly these fields:
{
    "verdict": "TRUE_POSITIVE" or "FALSE_POSITIVE" or "NEEDS_INVESTIGATION",
    "confidence": "HIGH" or "MEDIUM" or "LOW",
    "blast_radius": "<who and what is affected, including lateral scope>",
    "recommended_action": "close_as_fp" or "investigate_independently" or "suspend_session" or "escalate_tier2" or "legal_hold" or "monitor_and_watch",
    "action_rationale": "<one sentence: why this action and not another>",
    "reasoning": "<the specific evidence that drove your verdict>",
    "what_would_change_this": "<what additional context would flip or strengthen this verdict>"
}
Do not include any text outside the JSON object. Do not add markdown formatting.
"""
 
COT_STEPS = """Work through the following in order:
1. What did the SIEM rule trigger on? Is the trigger technically valid?
2. What context fields are present that the rule may not have considered?
3. What does the device recognition status tell you?
4. What does the prior alert history tell you?
5. Are there any signals that individually look suspicious but that have
   an innocent explanation in combination with other fields?
6. What is your verdict and confidence level?
7. What is the appropriate first action — and why NOT a different action?
8. What additional context would change your assessment?"""
 
# ─────────────────────────────────────────────────────────────
# One-shot and few-shot examples
# ─────────────────────────────────────────────────────────────
 
EXAMPLE_TP_1 = """
EXAMPLE — TRUE POSITIVE:
Alert: Auth success from Lagos, NG 38 minutes after session in Chicago, US.
Unrecognized device, no MFA, no travel notice on file. User has no prior alerts.
 
Output:
{
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "blast_radius": "Single user account compromised. Risk of lateral movement to all SSO-connected applications.",
    "recommended_action": "suspend_session",
    "action_rationale": "High confidence compromise — revoke session immediately to limit blast radius before independent investigation.",
    "reasoning": "38-minute delta across 9,600km is physically impossible. No MFA, unrecognized device, no travel notice, no prior FP history.",
    "what_would_change_this": "A recognized device or confirmed travel notice would reduce confidence significantly."
}
"""
 
EXAMPLE_TP_2 = """
EXAMPLE — TRUE POSITIVE:
Alert: Auth success from Beijing, CN 51 minutes after session in New York, US.
Unrecognized device, password-only auth, no MFA. No travel notice. User flagged
for offboarding next week.
 
Output:
{
    "verdict": "TRUE_POSITIVE",
    "confidence": "HIGH",
    "blast_radius": "Single user account. Elevated risk given pending offboarding — attacker may be targeting data before access is revoked.",
    "recommended_action": "suspend_session",
    "action_rationale": "Physically impossible travel, no MFA, unrecognized device, and offboarding context all point to active compromise requiring immediate containment.",
    "reasoning": "51-minute delta across 11,000km is physically impossible. Password-only auth with unrecognized device. Offboarding status elevates urgency.",
    "what_would_change_this": "VPN exit node confirmation or a recognized device would require re-evaluation."
}
"""
 
EXAMPLE_FP_1 = """
EXAMPLE — FALSE POSITIVE:
Alert: Auth success from London, GB 920 minutes after session in Philadelphia, US.
Recognized corporate device, MFA approved, travel notice on file for London conference.
User has 3 prior identical alerts — all cleared as FP during business travel.
 
Output:
{
    "verdict": "FALSE_POSITIVE",
    "confidence": "HIGH",
    "blast_radius": "None. Activity consistent with authorized business travel.",
    "recommended_action": "close_as_fp",
    "action_rationale": "Travel notice, recognized device, and prior cleared pattern confirm this is expected behavior.",
    "reasoning": "920-minute delta is consistent with a transatlantic flight. Device recognized, MFA approved, travel notice filed 4 days in advance.",
    "what_would_change_this": "An unrecognized device or absence of the travel notice would require investigation."
}
"""
 
EXAMPLE_FP_2 = """
EXAMPLE — FALSE POSITIVE:
Alert: Auth success from Amsterdam, NL 18 minutes after session in Seattle, US.
Source IP resolves to known corporate VPN exit node (engineering-approved).
Recognized device, YubiKey MFA. User is on the Security team.
 
Output:
{
    "verdict": "FALSE_POSITIVE",
    "confidence": "HIGH",
    "blast_radius": "None. Geo anomaly is explained by VPN exit node routing, not physical travel.",
    "recommended_action": "close_as_fp",
    "action_rationale": "Known corporate VPN exit node confirmed by ip_type field. Recognized device and hardware MFA eliminate compromise risk.",
    "reasoning": "Amsterdam IP is a documented corporate Mullvad VPN exit node. Physical location is Seattle. YubiKey MFA and recognized device rule out account takeover.",
    "what_would_change_this": "An unrecognized device or absence of VPN exit node confirmation would warrant investigation."
}
"""
 
 
# ══════════════════════════════════════════════════════════════
# PROMPT VARIANTS
# ══════════════════════════════════════════════════════════════
 
PROMPTS = {

# **Technique 1: ZERO-SHOT**      
# -------------------------------------------------------------
# No examples, no persona, no reasoning instruction.     
# Variable between v1 and v2: presence of output schema. 
 
# v1 — Zero-shot, no schema
# Claude formats output however it chooses.
# Every other variant should outperform this.
"v1_zeroshot_baseline": """
You are a security analyst. Review the following Datadog security signal
and produce a triage decision. Include your verdict, confidence level,
recommended action, and reasoning.
 
ALERT:
""",
 
# v2 — Zero-shot + structured output schema
# Tests what schema constraint alone adds over v1.
# Same zero guidance — only difference is format enforcement.
"v2_zeroshot_structured": f"""
You are a security analyst. Review the following Datadog security signal
and produce a triage decision.
 
{OUTPUT_SCHEMA}
 
ALERT:
""",

# **Technique 2: ONE-SHOT**                                  
# -------------------------------------------------------------
# Exactly one example before the alert.                  
# Variable between v3 and v4: example type (TP vs FP).  
# Tests whether a single example creates directional     
 # bias in the model's verdicts.  
 
# v3 — One-shot with a single TP example
# Hypothesis: model will tend to overcall TPs —
# particularly on alerts 3 and 5 (the FP traps).
"v3_oneshot_tp": """
You are a security analyst. Review the following security alert and produce
a triage decision. Study the example below before making your assessment.
 
{EXAMPLE_TP_1}
 
{OUTPUT_SCHEMA}
 
Now triage this alert:
 
ALERT:
""",
 
# v4 — One-shot with a single FP example
# Hypothesis: model will tend to undercall TPs —
# particularly on alerts 1 and 4 (the clear TPs).
"v4_oneshot_fp": f"""
You are a security analyst. Review the following security alert and produce
a triage decision. Study the example below before making your assessment.
 
{EXAMPLE_FP_1}
 
{OUTPUT_SCHEMA}
 
Now triage this alert:
 
ALERT:
""",

# **Technique 3: FEW-SHOT**                                  
# -------------------------------------------------------------
# Multiple examples before the alert.                    
# Variable between v5 and v6: example balance.           
# Tests whether a balanced vs biased example set        
# produces better calibrated verdicts.                   
 
# v5 — Few-shot, TP-heavy (2 TP + 1 FP)
# Slightly biased toward TP. Tests if even mild imbalance
# causes overcalling on ambiguous or FP alerts.
"v5_fewshot_tp_heavy": f"""
You are a security analyst. Review the following security alert and produce
a triage decision. Study the examples below before making your assessment.
 
{EXAMPLE_TP_1}
 
{EXAMPLE_TP_2}
 
{EXAMPLE_FP_1}
 
{OUTPUT_SCHEMA}
 
Now triage this alert:
 
ALERT:
""",
# v6 — Few-shot, balanced (2 TP + 2 FP)
 # Equal representation. Hypothesis: produces the best
 # calibration of all few-shot variants.

 "v6_fewshot_balanced": f"""
You are a security analyst. Review the following security alert and produce
a triage decision. Study the examples below — they show both true positives
and false positives to illustrate what distinguishes them.
 
{EXAMPLE_TP_1}
 
{EXAMPLE_FP_1}
 
{EXAMPLE_TP_2}
 
{EXAMPLE_FP_2}
 
{OUTPUT_SCHEMA}
 
Now triage this alert:
 
ALERT:
""",

# **Technique 4: ROLE-BASED**                                
# -------------------------------------------------------------
# Persona assignment with domain expertise.             
# Variable between v7 and v8: depth of context.         
# Tests whether institutional knowledge beyond the role 
# description meaningfully improves FP detection.        

 
# v7 — Role-based, persona only
# Strong analyst persona, no extra context injected.
# Tests what the role definition alone contributes.
"v7_role_basic": f"""
{ROLE}
 
{OUTPUT_SCHEMA}
 
ALERT:
""",
# v8 — Role-based + institutional context
# Same persona as v7 plus organizational knowledge the
# SIEM does not have: VPN topology, gateway routing,
# travel notice policy, insider risk indicators.
# Expected to be the strongest FP detection variant.
"v8_role_enriched": f"""
{ROLE}
 
Before triaging, review the following institutional context
that applies to all alerts:
 
ORGANIZATIONAL CONTEXT:
- SSO authentication (Okta) is routed through corporate internet gateways.
  The geo-location of an auth event may reflect a gateway exit point, not
  the user's physical location. Always check ISP and ip_type fields before
  concluding a geo anomaly is a real travel event.
- The company operates a corporate Mullvad VPN deployment. Known VPN exit
  nodes are tagged with known_corporate_vpn: true. Auth from these IPs is
  expected and should not be treated as geo anomalies.
- Travel notices are submitted by users via Okta before business travel.
  travel_notice_on_file: true is a strong FP signal for impossible travel alerts.
- For data exfiltration alerts, cross-reference user_context.resignation_submitted.
  A user who has submitted resignation and is downloading at anomalous volume
  and time is an elevated insider threat signal.
- Standard triage workflow: always investigate independently using available
  signal data BEFORE contacting the user. Contacting a potential attacker who
  has compromised an account alerts them to detection.
 
{OUTPUT_SCHEMA}
 
ALERT:
""",

# **Technique 5: CHAIN-OF-THOUGHT**                          ║
# -------------------------------------------------------------
# Explicit step-by-step reasoning before verdict.        
# Variable between v9 and v10: presence of output schema.
# Tests whether schema constraint improves CoT output    
# consistency without sacrificing reasoning quality.     
 
# v9 — Chain-of-thought, free-form output
# Same COT_STEPS as v10, no schema. Claude formats freely.
# Reveals raw reasoning quality — useful for finding cases
# where correct verdicts rest on flawed logic.
"v9_cot_freeform": f"""
You are a Senior SOC Analyst. Triage the following security alert by
reasoning through each piece of evidence step by step before reaching
a verdict. Do not jump to conclusions.
 
{COT_STEPS}
 
ALERT:
""",
 
# v10 — Chain-of-thought + structured output
# Same COT_STEPS as v9, adds OUTPUT_SCHEMA after reasoning.
# Hypothesis: best overall performer — sound reasoning AND
# consistent, parseable output.
"v10_cot_structured": f"""
You are a Senior SOC Analyst. Triage the following security alert using
a two-step process. Do not jump to conclusions.
 
STEP 1 — REASON:
{COT_STEPS}
 
STEP 2 — OUTPUT:
After completing your reasoning above, produce your final triage decision:
 
{OUTPUT_SCHEMA}
 
ALERT:
""",
 
}
 
 
# ── Quick validation ──────────────────────────────────────────
if __name__ == "__main__":
    techniques = {
        "Zero-shot":       ["v1_zeroshot_baseline", "v2_zeroshot_structured"],
        "One-shot":        ["v3_oneshot_tp", "v4_oneshot_fp"],
        "Few-shot":        ["v5_fewshot_tp_heavy", "v6_fewshot_balanced"],
        "Role-based":      ["v7_role_basic", "v8_role_enriched"],
        "Chain-of-thought":["v9_cot_freeform", "v10_cot_structured"],
    }
    print(f"Loaded {len(PROMPTS)} prompt variants across 5 techniques.\n")
    for technique, variants in techniques.items():
        print(f"  {technique}")
        for v in variants:
            word_count = len(PROMPTS[v].split())
            print(f"    {v:<30}  ~{word_count} words")
        print()