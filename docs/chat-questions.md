# Questions for the analysts' chat

Generated from `tests/chat-questions.yaml` by `scripts/make_chat_guide.py`: add a question there,
then run `python scripts/make_chat_guide.py --write`. The test suite checks that each question names
a tool that exists, with parameters it takes, and that this page is up to date. Set-up of the chat:
[`chat.md`](chat.md).

The chat answers in the language of the question. It reads, and prepares the actions of the list
below without running them: a validator confirms each on the review page (« Actions »). It never
changes a decision, sends a ticket or validates an alert. Every question and every action is in the
audit journal, with who asked. It answers for one tenant, from the decision service (the daily
run), the watch, the detection service, the dispatch service and the shared intelligence service,
whichever run for that tenant.

How to ask:

- Dates and times are in the tenant's time zone: « depuis hier 18 h », « entre le 1er et le 31
  octobre », « depuis lundi 9 h ».
- Name things the way A2VM does: a CVE (`CVE-2024-3094`), an asset as the chat listed it
  (`host:web01.lab.example`, or simply `web01`), a level (ACT, ATTEND, TRACK).
- Long answers come in pages: « la suite », « les 20 suivantes ».
- Ask for the reason: « pourquoi ? » after a decision gives its justification and its SSVC inputs.
- When no tool covers a question, the chat must say so rather than answer « aucun ». The last table
  lists the questions it cannot answer yet.

## The watch and the new CVEs

**`list_new_cves`**: the CVEs published or updated in a period, whoever they concern, and the alert the watch drafted for this tenant, if any.

- Quelles CVE ont été publiées depuis hier, avec leur heure de découverte ?
- Quelles nouvelles CVE critiques depuis lundi 9 h ?
- Quelles CVE ont été ajoutées au KEV cette semaine ?

**`list_alerts`**: the watch's alerts for the tenant in a period, with their status (pending, validated, sent...).

- Quelles alertes entre hier 18 h et ce matin 9 h ?

**`get_alert`**: one alert: its sheet for the client and its journal (drafted, validated, sent, by whom).

- Que dit l'alerte numéro 42 ?

**`list_radar_events`**: the major vulnerabilities the watch team found and validated (radar).

- Qu'a trouvé le radar depuis lundi ?
- La CVE-2024-3094 est-elle sur le radar ?

**`get_watch_status`**: the watch's last passage and the sources in error.

- La veille tourne-t-elle ? Quelles sources sont en erreur ?

## Are we concerned, and why

**`get_cve`**: one CVE as the run knows it, the assets it concerns and those with a version not affected.

- Sommes-nous concernés par la CVE-2024-3094 ?

**`find_component`**: the assets that carry a package or product, vulnerable or not, with its versions.

- Quels actifs ont OpenSSL 3.0 ?

**`list_applications`**: the applications the EDRs list, and whether their CPE is validated.

- Quelles applications n'ont pas encore de CPE validé ?

**`get_run_summary`**: the overview of the latest run: decisions per level, exposure, KEV, top assets and CVEs, SLA.

- Où en sommes-nous ?

**`search_decisions`**: the decisions (one per CVE and asset) with filters: level, exposure, KEV, EPSS, review, SLA.

- Quelles décisions ACT exposées sur Internet ?
- Quelles CVE du KEV avec un EPSS supérieur à 50 % ?
- Quelles décisions demandent une revue ?
- Qu'est-ce qui passe en retard de SLA cette semaine ?

**`get_decision`**: one decision in full: why this level, its SSVC inputs, fixes, due dates.

- Pourquoi la CVE-2024-3094 est-elle en ACT sur web01 ?

**`get_asset`**: one asset, its context and its decisions.

- Que sait-on de web01 ?
- D'où vient l'exposition de l'image vllm/vllm-openai:latest ?

## What changed, what was fixed, what to do

**`what_changed`**: the decisions new, gone or at another level since the run before, and why.

- Qu'est-ce qui a changé depuis le run d'hier ?

**`list_closed_findings`**: the findings fixed in a period, confirmed by a new scan.

- Quelles vulnérabilités ont été corrigées en octobre ?

**`list_unverified_findings`**: the findings gone while their asset was not scanned again.

- Quelles corrections déclarées ne sont pas encore confirmées par un scan ?

**`get_fix_plan`**: what to apply on one asset, in order: the fix that clears most ACT first.

- Quels correctifs appliquer sur web01, dans quel ordre ?

**`list_tickets`**: the remediation tickets sent to the ITSM, with their numbers and states.

- Combien de tickets envoyés à iTop en octobre, avec leurs numéros ?

## Coverage of the assets

**`list_coverage`**: each host against the CMDB: covered, partial, stale, never scanned, not in the CMDB.

- Quels actifs de la CMDB ne sont jamais scannés ?

## Documents to send

**`export_decisions`**: a Word, PowerPoint or CSV document of decisions, to download.

- Fais-moi un Word des ACT exposées

## Actions, confirmed by a person

**`request_connector_run`**: prepares a request to run a connector now (a CMDB sync, a scan): a validator confirms it on the review page, the collector runs it within minutes; the chat never runs it itself.

- Lance une synchro CMDB
- Relance le scan OpenVAS du collecteur lan

**`list_actions`**: the requests and their state: proposed, confirmed, taken, done, failed, cancelled, expired.

- Ma synchro CMDB est-elle terminée ?
- Quelles actions attendent une confirmation ?

## Who did what

**`get_audit`**: the audit journal: the chat's questions, the actions, the validations, with who and when.

- Qui a lancé la synchro CMDB hier ?
- Qui a validé l'alerte 42 ?
- Qu'a demandé ana@example.org au chat cette semaine ?

## The platform itself

**`list_runs`**: the daily runs kept, with their date and counts.

- Quand a tourné le dernier run ?

**`get_platform_status`**: the version of each service and of the latest run, its LLM and cost, the next daily run, collectors late.

- Quelle version d'A2VM tourne sur mon tenant ?
- Le run de ce matin est-il terminé, avec quel LLM, et combien a-t-il coûté ?
- Combien de temps verdict a-t-il tourné, et sur combien de findings ?
- Tout est-il à jour ?
- Quand les décisions seront-elles mises à jour ?

**`list_collectors`**: each collector and source: last push, age, late or refused, connector, agent's version, and the next and last run of each connector (the next scans).

- Quels collecteurs remontent des données ?
- Quand le connecteur OpenVAS a-t-il remonté pour la dernière fois ?
- Quelle version tourne sur le collecteur lan ?
- Un collecteur est-il muet ou en retard ?
- Quand aura lieu le prochain scan ?
- Quand le prochain scan OpenVAS du collecteur lan ?

## Not answered yet

| Question | Why |
| --- | --- |
| Quels serveurs n'ont pas été vus depuis 30 jours ? | list_coverage has no filter on the last time seen |
| Quel est le délai moyen de correction par priorité ? | the portal's dashboards, not the chat |
