Improve ModelGuard CLI usability by implementing a polished help interface.

Requirements:

1. Support:
   -h
   --help

2. Help output should include:
   - project description
   - authorised-use notice
   - usage examples
   - explanation of targets
   - explanation of report generation
   - explanation of --limit
   - explanation of timestamped filenames
   - example Ollama scan commands
   - exit code meanings

3. Ensure help formatting is clean and readable:
   - grouped arguments
   - wrapped text
   - examples section
   - defaults where relevant

4. Add CLI version support:
   --version

5. Example expected commands:
   python scanner.py --target ollama --model deepseek-r1:14b
   python scanner.py --target ollama --model llama3 --limit 2
   python scanner.py --target ollama --model mistral --out reports/test.md

6. Exit codes section should explain:
   0 = completed successfully
   1 = findings exceeded threshold
   2+ = scanner/runtime/configuration errors

7. Add tests covering:
   - -h
   - --help
   - --version
   - invalid argument handling

8. Keep dependencies minimal.
9. Do not add cloud support yet.
10. Do not rename the project.

After changes run:
python -m pytest -q
