# Contributing

Contributions are welcome under the project's license, AGPL-3.0-only.

- **Sign-off (DCO).** Every commit carries a `Signed-off-by:` line (`git commit -s`), certifying the
  Developer Certificate of Origin 1.1 (https://developercertificate.org/): you wrote the change or
  have the right to submit it under the project's license. If you contribute on behalf of your
  employer, make sure your employer allows it.
- **No real data.** Examples and test fixtures are fictitious (`*.example`, RFC 5737 addresses,
  synthetic `CVE-2099-*` records). Client profiles, contacts, scan targets and results never go in
  this repository: they live in the client projects.
- **Checks.** `ruff check .`, `ruff format --check .` and `pytest -q` pass before a merge request.
- **Decisions stay deterministic.** The LLM may write prose and propose flagged values; it never
  makes a triage decision.

Project documents are written in English.
