Rename the project from garak_poc to ModelGuard.

Requirements:

1. Rename Python package:
   garak_poc -> modelguard

2. Rename all imports accordingly.

3. Update branding everywhere:
   - README
   - CLI help text
   - report titles
   - HTML titles
   - Markdown headers
   - JSON metadata
   - scanner banner/version output
   - comments/docstrings where appropriate

4. Preserve functionality and tests.

5. Do NOT rename architecture pack files.

6. Ensure commands become:
   python scanner.py ...
   internally using modelguard package imports.

7. Add README wording:
   "Inspired by NVIDIA garak."

8. Ensure generated reports display:
   "ModelGuard Scan Report"

9. Run:
   python -m pytest -q

10. Do not add new dependencies.

