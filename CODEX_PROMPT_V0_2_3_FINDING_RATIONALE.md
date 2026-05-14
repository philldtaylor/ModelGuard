Improve ModelGuard finding rationale selection.

Problem:
Findings sometimes show a confusing rationale/evidence from a detector that did not actually cause the WARN/FAIL.

Example:
A prompt injection finding may be WARN because refusal_language warned, but the report rationale says "Response does not contain a realistic secret", which is from a PASS detector.

Implement:

1. Finding rationale should prioritize detector results that contributed to the final status:
   - For FAIL finding: prefer FAIL detector rationale/evidence.
   - For WARN finding: prefer WARN detector rationale/evidence.
   - Only fall back to PASS detector rationale if no WARN/FAIL detector exists.

2. Markdown and HTML reports should clearly show:
   - Primary detector
   - Primary rationale
   - Primary evidence
   - All detector results as they already do today

3. JSON findings should include:
   - primary_detector_id
   - primary_rationale
   - primary_evidence

4. Update tests for:
   - WARN finding uses WARN detector rationale, not PASS detector rationale
   - FAIL finding uses FAIL detector rationale
   - fallback still works if all detectors PASS but a finding somehow exists

5. Keep dependencies minimal.
6. Do not add cloud support.
7. Do not rename the project.

After changes, run:
python -m pytest -q
