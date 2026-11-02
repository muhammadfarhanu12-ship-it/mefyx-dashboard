"""Evaluate the full scan pipeline on any labeled JSON set: python scripts/evaluate_detection_sets.py tests/data/<set>.json -v
Format: [{"id","category","label":"malicious|benign","prompt","untrusted_content"?}]. Use a FRESH set for accuracy estimates."""
import json, sys, os, warnings, logging
warnings.filterwarnings("ignore"); logging.disable(logging.CRITICAL)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.security.security_enforcement_layer import SecurityEnforcementInput
from app.services.security_service import scan_prompt
from collections import defaultdict
data = json.load(open(sys.argv[1]))
verbose = "-v" in sys.argv
res = defaultdict(lambda: dict(TP=0,FN=0,TN=0,FP=0)); fn=[]; fp=[]
for c in data:
    r = scan_prompt(c["prompt"], security_tier="PRO", enable_ai=False,
        enforcement_input=SecurityEnforcementInput(prompt=c["prompt"], session_id="s-"+c["id"],
            conversation_id=c["id"], untrusted_content=c.get("untrusted_content")))
    dec = str(r.get("decision") or "").upper(); st = str(r.get("status") or "").upper()
    flagged = dec in {"BLOCK","SANITIZE"} or st in {"BLOCKED","REDACTED"}
    k = c["category"]
    if c["label"]=="malicious":
        res[k]["TP" if flagged else "FN"]+=1
        if not flagged: fn.append(c)
    else:
        res[k]["FP" if flagged else "TN"]+=1
        if flagged: fp.append((c,dec,st))
T=dict(TP=0,FN=0,TN=0,FP=0)
for k,v in sorted(res.items()):
    for kk in T: T[kk]+=v[kk]
    print(f"{k:22s} {v}")
tp,fn_,tn,fp_=T["TP"],T["FN"],T["TN"],T["FP"]
print("\nOVERALL", T, f"recall={tp/max(1,tp+fn_):.3f} precision={tp/max(1,tp+fp_):.3f} FPR={fp_/max(1,fp_+tn):.3f} accuracy={(tp+tn)/len(data):.3f}")
if verbose:
    print("\n--- MISSED ATTACKS ---")
    for c in fn: print(f"[{c['category']}] {c['prompt'][:140]!r}" + (f"  (+untrusted)" if c.get('untrusted_content') else ""))
    print("\n--- FALSE POSITIVES ---")
    for c,d,s in fp: print(f"[{d}/{s}] {c['prompt'][:140]!r}")