Improve garak_poc report file naming.

Implement timestamped report filenames.

Requirements:

1. If the user specifies:
   --out reports/result.md

   the scanner should automatically generate:
   reports/2026-05-13_11-49-41_result.md
   reports/2026-05-13_11-49-41_result.json
   reports/2026-05-13_11-49-41_result.html

2. Timestamp format:
   YYYY-MM-DD_HH-MM-SS

3. Use local execution time for filenames.

4. Ensure filenames are filesystem safe.

5. Update CLI summary output to print the actual generated filenames.

6. Preserve backward compatibility:
   - if users explicitly pass a filename with an existing timestamp, do not duplicate timestamps
   - if no --out is provided, generate a sensible default filename using model name and timestamp

7. Update tests for:
   - timestamped filename generation
   - extension handling
   - HTML/JSON/Markdown filename consistency
   - duplicate timestamp avoidance

8. Do not add external dependencies.

After changes run:
python -m pytest -q
