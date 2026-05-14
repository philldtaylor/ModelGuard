Add report comparison functionality to ModelGuard.

Goal:
Allow users to compare multiple JSON scan reports and generate a single model comparison report.

CLI requirements:
1. Support a compare mode:
   python scanner.py compare reports/*.json --out reports/model-comparison.html

2. The compare command should accept:
   - one or more JSON report paths
   - --out output path, default reports/comparison.html
   - --format html|md|json, default html if extension not clear

3. Comparison output should include:
   - compared report filenames
   - model names
   - target types
   - scan timestamps
   - total probes
   - PASS/WARN/FAIL/ERROR counts
   - highest severity
   - elapsed runtime
   - average probe latency
   - table of probe results by model
   - list of probes where model outcomes differ
   - fastest model
   - model with fewest FAIL results
   - model with fewest WARN+FAIL results

4. Generate self-contained HTML with embedded CSS.
   - Also support Markdown and JSON if straightforward.
   - Escape all report content safely.

5. Add tests for:
   - loading multiple JSON reports
   - summary comparison
   - differing probe outcomes
   - HTML output creation
   - safe HTML escaping
   - CLI compare invocation

6. Do not run model scans in tests.
7. Keep dependencies minimal.
8. Do not add cloud support yet.
9. Do not rename the project.

After changes run:
python -m pytest -q
