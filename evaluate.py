import json
import os
import time
 
import anthropic
from dotenv import load_dotenv
 
from alerts import ALERTS
from prompts import PROMPTS

## Configuration
MODEL          = "claude-haiku-3-5-20251001"
MAX_TOKENS     = 1024
OUTPUT_FILE    = "outputs.json"
SLEEP_BETWEEN  = 0.5   # seconds between API calls — avoids rate limits

# Variants that return free-form text (no JSON schema enforced).
# Verdict extraction is attempted via keyword matching, not parsing.
FREEFORM_VARIANTS = {"v1_zeroshot_baseline", "v9_cot_freeform"}