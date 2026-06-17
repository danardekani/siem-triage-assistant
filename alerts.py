"""
alerts.py — SIEM Triage Assistant
Test alert inputs modeled after Datadog Security Signal output format.
5 scenarios designed to test different LLM reasoning failure modes.

Ground truth verdicts are documented here and used as the evaluation
baseline. These reflect real SOC judgment — not algorithmic outputs.
"""

ALERTS = [

    # ─────────────────────────────────────────────────────────────
    # ALERT 1: Impossible Travel — Clear True Positive
    # Reasoning challenge: straightforward, but sets the baseline.
    # A model that gets this wrong fails on everything.
    # Ground truth: TRUE_POSITIVE | Confidence: HIGH
    # ─────────────────────────────────────────────────────────────
    {
        "alert_id":               "DD-SIG-2025-0471",
        "rule_name":              "Impossible Travel Detected",
        "rule_id":                "sec-rule-imp-travel-001",
        "severity":               "HIGH",
        "status":                 "open",
        "timestamp_utc":          "2025-06-14T03:17:42Z",

        "affected_user":          "s.patel@contrastsecurity.com",
        "user_department":        "Engineering",
        "user_role":              "Software Engineer",
        "manager":                "t.nguyen@contrastsecurity.com",

        "event_type":             "auth_success",
        "application":            "Okta SSO",
        "auth_method":            "password",
        "mfa_used":               False,

        "current_session": {
            "source_ip":          "41.202.219.11",
            "geo_city":           "Lagos",
            "geo_country":        "NG",
            "isp":                "MTN Nigeria",
            "device_id":          "UNKNOWN",
            "device_recognized":  False,
            "user_agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        },

        "prior_session": {
            "source_ip":          "192.168.1.45",
            "geo_city":           "Phoenixville",
            "geo_country":        "US",
            "device_id":          "DEV-S-PATEL-MBP-001",
            "device_recognized":  True,
            "timestamp_utc":      "2025-06-14T02:25:11Z"
        },

        "travel_delta_minutes":   52,
        "geo_distance_km":        9_841,
        "travel_notice_on_file":  False,
        "prior_alerts_90d":       0,
        "siem_confidence":        0.94,

        # Ground truth — set by analyst (you), used for evaluation scoring
        "_ground_truth": {
            "verdict":            "TRUE_POSITIVE",
            "confidence":         "HIGH",
            "reasoning":          (
                "Auth success from Lagos, NG 52 min after session in Phoenixville, US — "
                "physically impossible. Unrecognized device, no MFA, no travel notice on file."
            )
        }
    },

    # ─────────────────────────────────────────────────────────────
    # ALERT 2: Brute Force → Successful Auth — Ambiguous
    # Reasoning challenge: 14 failures then success looks like
    # credential stuffing, but the IP and device are recognized.
    # A confident TP verdict here is a calibration failure.
    # Ground truth: NEEDS_INVESTIGATION | Confidence: MEDIUM
    # ─────────────────────────────────────────────────────────────
    {
        "alert_id":               "DD-SIG-2025-0488",
        "rule_name":              "Brute Force Followed by Successful Authentication",
        "rule_id":                "sec-rule-brute-force-002",
        "severity":               "HIGH",
        "status":                 "open",
        "timestamp_utc":          "2025-06-15T08:44:03Z",

        "affected_user":          "m.chen@contrastsecurity.com",
        "user_department":        "Product",
        "user_role":              "Product Manager",
        "manager":                "l.harris@contrastsecurity.com",

        "event_type":             "auth_success_after_failures",
        "application":            "Okta SSO",
        "auth_method":            "password",
        "mfa_used":               True,
        "mfa_method":             "Okta Verify push",

        "current_session": {
            "source_ip":          "73.118.204.57",
            "geo_city":           "Philadelphia",
            "geo_country":        "US",
            "isp":                "Comcast Business",
            "device_id":          "DEV-M-CHEN-WIN-002",
            "device_recognized":  True,
            "user_agent":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
        },

        "failed_attempts": {
            "count":              14,
            "window_minutes":     11,
            "all_from_same_ip":   True,
            "all_same_device":    True,
            "error_type":         "invalid_credentials"
        },

        "travel_notice_on_file":  False,
        "prior_alerts_90d":       1,
        "prior_alert_detail":     "Similar brute force pattern 67 days ago — cleared after user confirmed forgot password post-vacation",
        "siem_confidence":        0.71,

        "_ground_truth": {
            "verdict":            "NEEDS_INVESTIGATION",
            "confidence":         "MEDIUM",
            "reasoning":          (
                "14 failed auths followed by success on recognized device from known IP. "
                "MFA approved. Prior identical pattern cleared as forgotten password 67 days ago."
            )
        }
    },

    # ─────────────────────────────────────────────────────────────
    # ALERT 3: Impossible Travel — Business Context False Positive
    # Reasoning challenge: the geo delta looks alarming, but
    # travel_notice_on_file is True and the device is recognized.
    # A TP verdict here is the FP trap. Claude must weigh context.
    # Ground truth: FALSE_POSITIVE | Confidence: HIGH
    # ─────────────────────────────────────────────────────────────
    {
        "alert_id":               "DD-SIG-2025-0501",
        "rule_name":              "Impossible Travel Detected",
        "rule_id":                "sec-rule-imp-travel-001",
        "severity":               "HIGH",
        "status":                 "open",
        "timestamp_utc":          "2025-06-16T14:02:19Z",

        "affected_user":          "r.johnson@contrastsecurity.com",
        "user_department":        "Sales",
        "user_role":              "VP of Sales",
        "manager":                "ceo@contrastsecurity.com",

        "event_type":             "auth_success",
        "application":            "Okta SSO",
        "auth_method":            "password",
        "mfa_used":               True,
        "mfa_method":             "Okta Verify push",

        "current_session": {
            "source_ip":          "82.132.220.14",
            "geo_city":           "London",
            "geo_country":        "GB",
            "isp":                "BT Business",
            "device_id":          "DEV-R-JOHNSON-MBP-001",
            "device_recognized":  True,
            "user_agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        },

        "prior_session": {
            "source_ip":          "192.168.10.5",
            "geo_city":           "Philadelphia",
            "geo_country":        "US",
            "device_id":          "DEV-R-JOHNSON-MBP-001",
            "device_recognized":  True,
            "timestamp_utc":      "2025-06-15T22:14:07Z"
        },

        "travel_delta_minutes":   948,
        "geo_distance_km":        5_703,
        "travel_notice_on_file":  True,
        "travel_notice_detail":   "London customer onsite — June 16-19. Submitted by user June 12.",
        "prior_alerts_90d":       2,
        "prior_alert_detail":     "Both prior alerts cleared as FP — same pattern during NY and Chicago travel",
        "siem_confidence":        0.88,

        "_ground_truth": {
            "verdict":            "FALSE_POSITIVE",
            "confidence":         "HIGH",
            "reasoning":          (
                "Travel notice on file 4 days prior for London June 16-19. "
                "Recognized corporate device, MFA approved, consistent with prior cleared travel alerts."
            )
        }
    },

    # ─────────────────────────────────────────────────────────────
    # ALERT 4: Insider Threat — Data Exfiltration Signal
    # Reasoning challenge: individual signals are weak, but
    # combined with HR context (resignation) the picture changes.
    # Claude must synthesize multiple weak signals into a verdict.
    # Ground truth: TRUE_POSITIVE | Confidence: HIGH
    # ─────────────────────────────────────────────────────────────
    {
        "alert_id":               "DD-SIG-2025-0519",
        "rule_name":              "Large Volume Data Download — Off Hours",
        "rule_id":                "sec-rule-dlp-exfil-004",
        "severity":               "MEDIUM",
        "status":                 "open",
        "timestamp_utc":          "2025-06-17T02:47:38Z",

        "affected_user":          "t.williams@contrastsecurity.com",
        "user_department":        "Engineering",
        "user_role":              "Senior Engineer",
        "manager":                "k.patel@contrastsecurity.com",

        "event_type":             "large_download",
        "application":            "Google Drive",
        "download_volume_gb":     2.3,
        "file_types":             ["zip", "pdf", "xlsx", "docx"],
        "folder_accessed":        "Shared Drive / Product Roadmap / Confidential",
        "auth_method":            "OAuth2",
        "mfa_used":               True,

        "current_session": {
            "source_ip":          "98.114.55.201",
            "geo_city":           "Philadelphia",
            "geo_country":        "US",
            "isp":                "Verizon Fios",
            "device_id":          "UNKNOWN",
            "device_recognized":  False,
            "user_agent":         "python-requests/2.31.0"
        },

        "user_context": {
            "resignation_submitted": True,
            "resignation_date":   "2025-06-14",
            "last_working_day":   "2025-06-28",
            "offboarding_started": False
        },

        "activity_baseline": {
            "avg_daily_download_gb":  0.08,
            "typical_work_hours":     "08:00-18:00 ET",
            "prior_drive_alerts":     0
        },

        "travel_notice_on_file":  False,
        "prior_alerts_90d":       0,
        "siem_confidence":        0.73,

        "_ground_truth": {
            "verdict":            "TRUE_POSITIVE",
            "confidence":         "HIGH",
            "reasoning":          (
                "2.3GB download (28x baseline) at 2:47 AM via python-requests on unrecognized device "
                "from user who submitted resignation 3 days prior. Confidential folder accessed."
            )
        }
    },

    # ─────────────────────────────────────────────────────────────
    # ALERT 5: Impossible Travel — VPN Exit Node False Positive
    # Reasoning challenge: the most technically sophisticated FP.
    # The IP resolves to a known corporate VPN exit in Amsterdam.
    # A model that only reads geo_country fires a TP. A model that
    # reasons about isp and device context catches the FP.
    # Ground truth: FALSE_POSITIVE | Confidence: HIGH
    # ─────────────────────────────────────────────────────────────
    {
        "alert_id":               "DD-SIG-2025-0534",
        "rule_name":              "Impossible Travel Detected",
        "rule_id":                "sec-rule-imp-travel-001",
        "severity":               "HIGH",
        "status":                 "open",
        "timestamp_utc":          "2025-06-17T16:33:55Z",

        "affected_user":          "a.kim@contrastsecurity.com",
        "user_department":        "Security",
        "user_role":              "Security Engineer",
        "manager":                "ciso@contrastsecurity.com",

        "event_type":             "auth_success",
        "application":            "Okta SSO",
        "auth_method":            "password",
        "mfa_used":               True,
        "mfa_method":             "hardware_key_yubikey",

        "current_session": {
            "source_ip":          "185.220.101.47",
            "geo_city":           "Amsterdam",
            "geo_country":        "NL",
            "isp":                "Mullvad VPN / Arelion",
            "ip_type":            "hosting_vpn_exit",
            "known_corporate_vpn": True,
            "vpn_note":           "IP is a known exit node for the corporate Mullvad VPN deployment. Engineering-approved.",
            "device_id":          "DEV-A-KIM-MBP-SEC-001",
            "device_recognized":  True,
            "user_agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
        },

        "prior_session": {
            "source_ip":          "192.168.1.88",
            "geo_city":           "Philadelphia",
            "geo_country":        "US",
            "device_id":          "DEV-A-KIM-MBP-SEC-001",
            "device_recognized":  True,
            "timestamp_utc":      "2025-06-17T16:21:04Z"
        },

        "travel_delta_minutes":   12,
        "geo_distance_km":        5_890,
        "travel_notice_on_file":  False,
        "prior_alerts_90d":       4,
        "prior_alert_detail":     "All 4 prior alerts on this user resolved as FP — same VPN exit node pattern. User is Security team, VPN usage expected.",
        "siem_confidence":        0.91,

        "_ground_truth": {
            "verdict":            "FALSE_POSITIVE",
            "confidence":         "HIGH",
            "reasoning":          (
                "Source IP 185.220.101.47 is a known corporate Mullvad VPN exit node (engineering-approved). "
                "Recognized device, YubiKey MFA. 4 prior identical alerts all cleared on same pattern."
            )
        }
    },
]


# ── Quick validation ──────────────────────────────────────────
if __name__ == "__main__":
    print(f"Loaded {len(ALERTS)} alert inputs.\n")
    for a in ALERTS:
        gt = a["_ground_truth"]
        print(
            f"  {a['alert_id']}  |  {a['rule_name']:<45}  |  "
            f"{gt['verdict']:<25}  |  Confidence: {gt['confidence']}"
        )