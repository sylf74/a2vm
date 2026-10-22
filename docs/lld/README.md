# Low-level designs

One document per pillar, kept with the code it describes and updated in the same merge request.
Each LLD is the C4 level 3 of one pillar of the high-level design ([`../hld/`](../hld/README.md));
the HLD holds goals, constraints, contracts and decisions, and the technical architecture document
(DAT: servers, zones, flows) lives outside the repository. The documents follow the same
arc42-based structure.

| Pillar | HLD chapter | LLD | Status |
| --- | --- | --- | --- |
| 1. VIA, Vulnerability Intelligence (`via`) | [10](../hld/10-vulnerability-intelligence.md) | — | To write |
| 2. Vulnerability Detection (`detect`) | [20](../hld/20-vulnerability-detection.md) | — | To write |
| 3. Triage & Prioritization (`verdict`) | [30](../hld/30-triage-prioritization.md) | [triage-prioritization.md](triage-prioritization.md) | Decision (`verdict run`) reporting dataset and exposure gaps as built in v0.11.4; asset context (`verdict.assets`) to add |
| 4. Dispatch & Capitalization (`dispatch`) | [40](../hld/40-dispatch-capitalization.md) | — (reporting database: [`docs/reporting.md`](../reporting.md)) | Reporting database in place (v0.11.5); LLD to write |
| 5. Emergency Actions | [50](../hld/50-emergency-actions.md) | — | Not started |
