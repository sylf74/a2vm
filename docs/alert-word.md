# The alert sheet in Word (v0.11.4)

The watch can attach the alert sheet as a Word file to the analysts' mail and to the client's mail.
The file is filled from a template with tags ([docxtpl](https://docxtpl.readthedocs.io/)): the
client's own layout, A2VM's facts.

## Setting it up for a client

1. In `client.yaml`:

   ```yaml
   alerts:
     attach: [docx]
     # word_template: templates/alert.docx   # default: this file when present, else the neutral one
   ```

2. Optional: the client's template in its project, `templates/alert.docx`. Start from a sheet the
   team already sends to that client and replace its content with the tags below, keeping its
   layout, styles, header and footer. Without it, the neutral template shipped with A2VM is used
   (`via/src/via/alert/templates/alert.docx`, built by `scripts/make_alert_template.py`).
3. The `validate` job checks the template (`via check-template templates/alert.docx`): it fails
   on a tag A2VM does not fill, or on a broken tag.

A client's template carries its branding and classification marks: it stays in the client project,
never in the A2VM repository.

## Editing a template in Word

The team may change wording, headings, order and styles. Keep each tag whole, typed in one go, with
the same formatting from `{{` to `}}`: Word splits text into runs when formatting changes in the
middle, and a split tag is no longer recognised.

| Form | Use |
| --- | --- |
| `{{ name }}` | A value |
| `{{r name }}` | A link (clickable, blue, underlined) |
| `{%p for x in list %}` … `{%p endfor %}` | Repeat the paragraphs in between; each `{%p … %}` alone in its paragraph |
| `{%p if cond %}` … `{%p else %}` … `{%p endif %}` | Keep paragraphs on a condition |
| `{%p for x in list %}` … `{%p else %}` … `{%p endfor %}` | The `else` paragraphs when the list is empty |
| `{% if cond %}…{% else %}…{% endif %}` | Choose words inside one paragraph |
| `{%tr for a in actifs %}` … `{%tr endfor %}` | Repeat a table row (each in a row of its own) |

## Tags

| Tag | Content | Source |
| --- | --- | --- |
| `titre` | Title of the alert, without the level | Publication or CVE |
| `niveau`, `date`, `source` | URGENT / INFORMATION, date of the sheet, publishing source | Watch |
| `pourquoi` | List: why this alert | Watch |
| `produit_description` | One sentence on the product; empty when unknown | LLM, guarded; else empty |
| `poc` | True when a proof of concept or an exploitation is known | KEV, CISA ADP, GTI, references |
| `risques` | List of risks | CERT-FR; else derived from the CVSS impacts |
| `cvss_version`, `cvss_score` | Highest CVSS of the alert | CVE records (CNA first) |
| `impact`, `description` | Main impact (one sentence), description | Same text as the mail |
| `exploitee` | Oui / Non | KEV or confirmed exploitation |
| `correctif_existe` | Oui / Non précisé | A fix is known |
| `contournement_existe` | Non précisé (workarounds are not read from the sources yet) | — |
| `cwes` | List; each `w.id`, `w.nom`, `w.lien` (link) | CVE records |
| `cves` | List; see below | CVE records |
| `actifs` | List of the client's assets concerned; each `a.nom`, `a.zone`, `a.exposition`, `a.version_installee`, `a.version_corrigee`, `a.responsable`, `a.source` | Same table as the mail |
| `correctifs` | List of fixes | CERT-FR, CSAF, fixed versions seen on the assets |
| `contournements` | List of workarounds (empty for now) | — |
| `delai` | Recommended delay (CISA BOD 26-04) | Pillar 3 |
| `references` | List of links | Publication, CVE records, vendors |

Each `c` of `cves`: `c.id`, `c.cvss_version`, `c.cvss_score`, `c.lien_cve` (link), `c.lien_cvss`
(link to the FIRST calculator of the vector's own version; empty without a vector), `c.vecteur`,
`c.complexite`, `c.privileges`, `c.interaction` (from the CVSS vector), `c.droits_privilegies`
(Oui when the SSVC Technical Impact is `total`), `c.composants` (list of affected products and
versions, from the CNA).

## Editing a sheet before sending

The analysts' mail says how. In short, in the client project, on the default branch:

- `edits/<alert id>.md`: the sheet's text, corrected (copy it from the link in the mail). It
  replaces the mail body. It may not cite a CVE the alert does not: such a sheet is not sent.
- `edits/<alert id>.docx`: the Word file, corrected (download it from the link in the mail,
  change it, upload it). It replaces the attachment.

Then ▶ on `send-alerts`: the job reads `edits/` from the head of the branch, sends, and records
in the journal which parts the analyst changed. The edited files stay in the project's history.
