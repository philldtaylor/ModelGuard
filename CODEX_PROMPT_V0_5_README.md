Improve the ModelGuard README so the repository looks professional and portfolio-ready.

Goals:
- Position ModelGuard as an enterprise-oriented AI security validation framework.
- Make the project understandable to hiring managers, security engineers, and developers.
- Keep wording accurate and professional.
- Avoid exaggerated claims.

README requirements:

1. Title:
   # ModelGuard

2. Add concise tagline:
   "AI security validation and model assurance framework for local and cloud-hosted LLM workloads."

3. Add sections:
   - Overview
   - Features
   - Supported Targets
   - Probe Categories
   - Example Workflow
   - Installation
   - Quick Start
   - Example Reports
   - Model Comparison
   - Safety and Authorised Use
   - Roadmap
   - Architecture
   - Inspiration / Acknowledgements

4. Include:
   - Markdown report example snippet
   - HTML comparison report example snippet
   - Example CLI commands
   - Screenshot placeholders users can later replace
   - Mention Ollama support
   - Mention future AWS Bedrock support
   - Mention timestamped reports
   - Mention JSON/Markdown/HTML outputs
   - Mention compare mode

5. Add realistic enterprise framing:
   - governance
   - model assurance
   - validation
   - AI workload security
   - safe testing

6. Add architecture summary:
   - adapters
   - probes
   - detectors
   - reporting
   - comparison engine

7. Add example compare command:
   python3 scanner.py compare reports/*.json --out reports/comparison.html

8. Add "Inspired by NVIDIA garak."

9. Add professional roadmap:
   - AWS Bedrock adapter
   - OpenAI-compatible APIs
   - CI/CD scanning
   - policy packs
   - SARIF output
   - telemetry export

10. Do NOT fabricate screenshots.
    Use placeholders like:
    docs/screenshots/model-comparison.png

11. Ensure README tone is:
    - professional
    - technical
    - concise
    - enterprise-oriented

12. Do not add badges yet.
13. Do not add new dependencies.
14. Preserve existing functionality/tests.

After edits run:
python3 -m pytest -q
