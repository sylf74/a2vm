# Low-level designs

One document per pillar, kept with the code it describes and updated in the same merge request.
Each LLD is the C4 level 3 of one pillar of the high-level design ([`../hld/`](../hld/README.md));
the HLD holds goals, constraints, contracts and decisions, and the technical architecture document
(DAT: servers, zones, flows) lives outside the repository. The documents follow the same
arc42-based structure; §1.1 of each lists the interfaces of its pillar with the others (what it
provides, what it consumes, what happens when the other side is missing), all of them in HLD §6.

| Pillar | HLD chapter | LLD | Status |
| --- | --- | --- | --- |
| 1. VIA, Vulnerability Intelligence (`via`) | [10](../hld/10-vulnerability-intelligence.md) | [vulnerability-intelligence.md](vulnerability-intelligence.md) | Records, watch and watch service as built in v0.16.2 |
| 2. Vulnerability Detection (`detect`) | [20](../hld/20-vulnerability-detection.md) | [vulnerability-detection.md](vulnerability-detection.md) | Collection, scans, declared inventory, external detection, collectors and detection service as built in v0.16.2 |
| 3. Triage & Prioritization (`verdict`) | [30](../hld/30-triage-prioritization.md) | [triage-prioritization.md](triage-prioritization.md) | Decision, restitution, asset context, decision service and tool server of the chat as built in v0.16.2 |
| 4. Dispatch & Capitalization | [40](../hld/40-dispatch-capitalization.md) | — | Not started |
| 5. Emergency Actions | [50](../hld/50-emergency-actions.md) | — | Not started |
