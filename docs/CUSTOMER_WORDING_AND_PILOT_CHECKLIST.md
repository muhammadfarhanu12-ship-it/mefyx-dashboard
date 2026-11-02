# Mefyx – Customer Wording & Pilot Checklist

*Every number below comes from measured tests (see "Where the numbers come from"). Re-measure after each
model/rule update and change the wording if the numbers change.*

---

## Part 1 – Customer-facing wording

### Headline (website / deck)
**efyx screens every AI request for prompt injection and financial-fraud attempts before it reaches your model.**

### One-paragraph description
Mefyx sits between your application and your AI provider. It inspects each request in real time –
including attached documents and web content – for prompt-injection and jailbreak attempts, attempts to
extract hidden instructions, social-engineering and fraud requests (phishing, fake invoices, OTP/PIN theft,
payment-redirection), and unsafe agent/tool instructions. Suspicious requests are blocked or flagged, and every
decision is logged for your security team.

### What it does (safe to say)
- Multi-layer detection: pattern rules, meaning-level analysis, and a trained classifier, working together.
- Understands disguised attacks – odd spacing, look-alike characters, typos, encoded text – and attacks written
  in 12+ languages, including English, Urdu (Roman), Arabic, Chinese, Spanish, French and German.
- Treats attached documents and web content as untrusted, so hidden instructions inside them are caught.
- Adds well under 50 ms to a request in our testing (about 8 ms average on standard hardware).
- Monitor mode lets you watch what Sentinel *would* block before you turn blocking on.
- Fails safe: if a scan cannot complete, the request is held rather than waved through (configurable).

### Accuracy statement (use exactly this, not a rounder number)
> In internal testing on attack wordings the system had never seen, Sentinel caught roughly **85%** of
> prompt-injection and fraud attempts while blocking **under 3%** of ordinary requests. No detection system
> is perfect; Sentinel is one layer of defence and is improved continuously from reviewed real-world traffic.

### Do **not** say
- "100% accurate", "unbeatable", "guaranteed protection", "stops all attacks", "zero false positives".
- That it replaces your provider's safety systems, access controls, or human approval for payments.
- Any accuracy number that has not been re-measured on the current version.

### Honest limits (put these in your docs / terms)
1. New attack styles will sometimes get through; new legitimate phrasing will sometimes be blocked.
2. Detection is strongest for the languages and attack types listed above and weaker elsewhere.
3. Sentinel screens text inputs; it does not inspect images, audio, or the model's own reasoning.
4. Customers remain responsible for approvals on high-value actions (keep human sign-off for payments).

### Short FAQ
**Will it block my normal users?** Rarely – under 3% of ordinary requests in our tests. Start in monitor mode to
see exactly what would be blocked before enforcing, and tell us about any mistake so it is fixed and added to the
regression tests.
**What do you store?** Request decisions and a short preview of flagged prompts are kept in the audit log for your
security team. Set your retention period and tell users in your privacy policy. *(Fill in your actual retention.)*
**Does it slow things down?** Typically about 8 ms per request.
**What happens if Sentinel has a problem?** By default requests are held rather than allowed unscanned.
**Can we tune it?** Yes – threshold, monitor/enforce mode, and which message roles are scanned are all settings.

---

## Part 2 – Pilot checklist (4 weeks)

### Before day 1 (all must be ticked)
- [ ] **Rotate every secret** that was in the original `.env` (database, JWT, API-key secret, provider keys). Delete old `.db` files.
- [ ] Production `.env` set from `.env.example`; `GATEWAY_SECURITY_MODE=monitor`.
- [ ] `pip install -r requirements.txt`; `pytest tests` passes on the deployed build.
- [ ] Real MongoDB, email and (if used) billing tested end to end once.
- [ ] Provider keys added and the **AI analysis stage enabled**; re-run `python scripts/evaluate_detection_sets.py tests/data/<set>.json`.
- [ ] Load test at 2× expected peak traffic; confirm latency and error rate.
- [ ] Audit-log retention decided and written into your privacy policy.
- [ ] A named person owns pilot reviews and a way to reach engineering fast.

### Weeks 1–2: watch (monitor mode – nothing is blocked)
- [ ] Daily: export `gateway_request_would_block` events (prompt preview, threat type, risk score).
- [ ] A reviewer labels each as `malicious` or `benign` (CSV with columns `prompt`, `label`).
- [ ] Also sample ~50 *unflagged* requests per day and label them – this finds **missed** attacks.
- [ ] `python scripts/promote_reviewed_samples.py reviewed.csv` → `python scripts/train_ml_layer.py` → `pytest`.
- [ ] Ship the retrained model/rules weekly; record the numbers each time.

### Week 3: tighten
- [ ] Check the false-positive share of would-block events. Raise `ML_BLOCK_THRESHOLD` (e.g. 0.70 → 0.75) if it is above target; lower it if too many attacks were missed.
- [ ] Run `python scripts/fuzz_robustness.py --min 0.85` to confirm obfuscated variants are still caught.
- [ ] Ask pilot customers for feedback on anything that was wrongly flagged.

### Week 4: decide (go / no-go for `enforce`)
Go only if **all** are true on at least 500 reviewed would-block events and 500 reviewed allowed requests:
- [ ] Reviewed would-block events that were really benign: **≤ 10%**
- [ ] Attacks found among reviewed *allowed* requests: **≤ 5%** of attacks seen
- [ ] No critical (money-moving or data-leaking) attack missed in the last 2 weeks
- [ ] p95 added latency **< 50 ms**; scan error rate **< 0.1%**
- [ ] Independent security test completed and findings fixed
- [ ] `AUTH_REQUIRE_TURNSTILE` enabled **only if** the sign-in/sign-up pages show the widget

If any box fails: stay in monitor mode, fix, and repeat another two weeks.

### After go-live
- [ ] Switch `GATEWAY_SECURITY_MODE=enforce`; keep weekly review for the first month, then monthly.
- [ ] Keep a one-click way to return to `monitor` mode.
- [ ] Re-measure and update any accuracy numbers shown to customers after every release.

---

## Where the numbers come from
- **~85% caught / 0% blocked**: held-out test set 5 (39 attacks, 43 harmless requests) – the learned layer was
  trained *without* it and the rules were never tuned to it. Small sample; treat as ±10 points.
- **<3% of ordinary requests blocked**: 184 everyday prompts (code, contracts, chat, 12 languages) with the
  learned layer trained without them: 3.3% blocked by the classifier, 0% by the rules.
- **~8 ms**: average full scan time measured on the development machine (100 requests).
- Leave-one-set-out cross-validation across all sets: ~85% recall at ~2% false positives (threshold 0.70).
- Limitation: all test data was authored by the development team, not real attackers. Real-world accuracy will
  differ – that is exactly what the pilot measures.