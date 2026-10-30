# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""Labels of the alert sheet and of its Word file, per language (v0.17.1).

A2VM writes in English; the sheet is the English reference an analyst validates and enriches.
For a contact in another language the sender sends a translation the analyst validated too
(`translate.py`). Labels written by code (headings, fixed phrases, table headers, Word values) come
from this catalogue, never from a model: in a language of the catalogue the headings of a
translation are set from here, and the Word file is filled in that language. A language outside
the catalogue gets the model's translation of the text and an English Word file.
"""

from __future__ import annotations

DEFAULT = "en"

LABELS: dict[str, dict[str, str]] = {
    "en": {
        "level.urgent": "URGENT",
        "level.info": "INFORMATION",
        "h.why": "Why this alert",
        "h.assets": "Your assets concerned",
        "h.cve": "CVE",
        "h.product": "Affected product",
        "h.type": "Vulnerability type",
        "h.cvss": "CVSS",
        "h.impact": "Main impact",
        "h.exploitation": "Exploitation status",
        "h.description": "Description",
        "h.delay": "Recommended remediation delay",
        "h.links": "Links",
        "why.default": "Publication about your products.",
        "why.source": "Source: {source} ({category})",
        "cat.institutional": "institutional source",
        "cat.vendor": "vendor / manufacturer",
        "cat.research": "research",
        "reason.kev": "active exploitation (CISA KEV catalog)",
        "reason.gti_active": "exploitation confirmed by Google Threat Intelligence",
        "reason.source": "publication {source}",
        "reason.cisa_poc": "exploitation or proof of concept reported by CISA",
        "reason.exposed_critical": "critical vulnerability on an internet-facing asset",
        "cve.none": "No CVE assigned yet.",
        "unspecified": "Not specified by the sources.",
        "cvss.none": "No CVSS score published yet.",
        "cvss.unpublished": "score not published",
        "q.critical": "critical",
        "q.high": "high",
        "q.medium": "medium",
        "q.low": "low",
        "q.none": "none",
        "versions.range": "{start} to {end} (excluded)",
        "versions.range_incl": "{start} to {end}",
        "impact.see": "See the description.",
        "desc.vendor": "Vendor description: “{text}”",
        "st.known": "Known exploitation",
        "st.exploit": "Public exploit",
        "st.fix": "Fix",
        "st.workaround": "Workaround",
        "st.workaround.none": "not specified by the sources, see the vendor advisories",
        "ex.kev": "yes — CISA KEV catalog",
        "ex.kev_added": " (added on {date})",
        "ex.gti": "yes — {state} exploitation (Google Threat Intelligence)",
        "ex.gti.wide": "widespread",
        "ex.gti.confirmed": "confirmed",
        "ex.gti_first": ", first exploitation seen on {date}",
        "ex.gti_unconfirmed": "reported, not confirmed to date (Google Threat Intelligence)",
        "ex.none": "no exploitation reported to date",
        "poc.reference": "yes — proof of concept referenced",
        "poc.gti": "yes — public exploit (Google Threat Intelligence)",
        "poc.none": "none found in the sources",
        "fix.available": "available — {fixes}",
        "fix.more": " (+{n} more)",
        "fix.advisories": "available — see the vendor advisories in the links",
        "fix.vendor": "see the vendor's advisory in the links",
        "fix.none": "no fix found to date in the sources",
        "fix.update": "{name}: update to {version}",
        "delay.text": "{delay} (CISA BOD 26-04).",
        "link.kev": "CISA KEV catalog",
        "assets.none": "- No asset identified with certainty.",
        "assets.inventory": "Inventory of {date} (last daily run).",
        "t.asset": "Asset",
        "t.zone": "Zone",
        "t.exposure": "Exposure",
        "t.installed": "Installed version",
        "t.fixed": "Fixed version",
        "t.owner": "Owner",
        "t.source": "Source",
        "exp.open": "open (internet)",
        "exp.controlled": "controlled",
        "exp.small": "restricted",
        "exps.external-scan": "external scan",
        "exps.declared": "declared",
        "exps.rule": "rule",
        "exps.default": "assumed",
        "exps.published": "published",
        "src.trivy": "package scan",
        "src.dnf-updateinfo": "dnf updates",
        "src.openvas": "network scan",
        "src.external-scan": "external scan",
        "src.inventory": "declared",
        "src.detected": "detected ({sources})",
        "src.declared": "declared",
        "src.watchlist": "watchlist",
        "src.cited": "product named by {source}",
        "label.exposed": "internet-facing",
        "label.not_exposed": "not internet-facing",
        "label.exposed_assumed": "internet-facing (assumed: exposure not declared)",
        "w.av.N": "Network",
        "w.av.A": "Adjacent network",
        "w.av.L": "Local",
        "w.av.P": "Physical",
        "w.ac.L": "Low",
        "w.ac.H": "High",
        "w.pr.N": "None",
        "w.pr.L": "Simple user authentication",
        "w.pr.H": "High privileges",
        "w.ui.N": "No",
        "w.ui.R": "Yes",
        "w.ui.P": "Yes (passive)",
        "w.ui.A": "Yes (active)",
        "w.risk.c": "Loss of data confidentiality",
        "w.risk.i": "Loss of data integrity",
        "w.risk.a": "Denial of service",
        "w.yes": "Yes",
        "w.no": "No",
        "w.unspecified": "Not specified",
        "w.unpublished": "not published",
        "the_source": "the source",
    },
    "fr": {
        "level.urgent": "URGENT",
        "level.info": "INFORMATION",
        "h.why": "Pourquoi cette alerte",
        "h.assets": "Vos actifs concernés",
        "h.cve": "CVE",
        "h.product": "Produit concerné",
        "h.type": "Type de vulnérabilité",
        "h.cvss": "CVSS",
        "h.impact": "Impact principal",
        "h.exploitation": "État d'exploitation",
        "h.description": "Description",
        "h.delay": "Délai de remédiation recommandé",
        "h.links": "Liens",
        "why.default": "Publication concernant vos produits.",
        "why.source": "Source : {source} ({category})",
        "cat.institutional": "source institutionnelle",
        "cat.vendor": "éditeur / constructeur",
        "cat.research": "recherche",
        "reason.kev": "exploitation active (catalogue KEV de la CISA)",
        "reason.gti_active": "exploitation confirmée par Google Threat Intelligence",
        "reason.source": "publication {source}",
        "reason.cisa_poc": "exploitation ou preuve de concept signalée par la CISA",
        "reason.exposed_critical": "vulnérabilité critique sur un actif exposé à Internet",
        "cve.none": "Aucune CVE attribuée à ce stade.",
        "unspecified": "Non précisé par les sources.",
        "cvss.none": "Pas encore de score CVSS publié.",
        "cvss.unpublished": "score non publié",
        "q.critical": "critique",
        "q.high": "élevé",
        "q.medium": "moyen",
        "q.low": "faible",
        "q.none": "aucun",
        "versions.range": "{start} à {end} (exclu)",
        "versions.range_incl": "{start} à {end}",
        "impact.see": "Voir la description.",
        "desc.vendor": "Description de l'éditeur : « {text} »",
        "st.known": "Exploitation connue",
        "st.exploit": "Exploit public",
        "st.fix": "Correctif",
        "st.workaround": "Contournement",
        "st.workaround.none": "non précisé par les sources, voir les avis éditeur",
        "ex.kev": "oui — catalogue KEV de la CISA",
        "ex.kev_added": " (ajout le {date})",
        "ex.gti": "oui — exploitation {state} (Google Threat Intelligence)",
        "ex.gti.wide": "généralisée",
        "ex.gti.confirmed": "confirmée",
        "ex.gti_first": ", première exploitation observée le {date}",
        "ex.gti_unconfirmed": "signalée, non confirmée à ce jour (Google Threat Intelligence)",
        "ex.none": "aucune exploitation signalée à ce jour",
        "poc.reference": "oui — preuve de concept référencée",
        "poc.gti": "oui — exploit public (Google Threat Intelligence)",
        "poc.none": "aucun identifié dans les sources",
        "fix.available": "disponible — {fixes}",
        "fix.more": " (+{n} autres)",
        "fix.advisories": "disponible — voir les avis éditeur en lien",
        "fix.vendor": "voir l'avis de l'éditeur en lien",
        "fix.none": "aucun correctif identifié à ce jour dans les sources",
        "fix.update": "{name} : mise à jour vers {version}",
        "delay.text": "{delay} (référentiel CISA BOD 26-04).",
        "link.kev": "Catalogue KEV de la CISA",
        "assets.none": "- Aucun actif identifié avec certitude.",
        "assets.inventory": "Inventaire du {date} (dernier traitement quotidien).",
        "t.asset": "Actif",
        "t.zone": "Zone",
        "t.exposure": "Exposition",
        "t.installed": "Version installée",
        "t.fixed": "Version corrigée",
        "t.owner": "Responsable",
        "t.source": "Source",
        "exp.open": "ouverte (Internet)",
        "exp.controlled": "contrôlée",
        "exp.small": "restreinte",
        "exps.external-scan": "scan externe",
        "exps.declared": "déclarée",
        "exps.rule": "règle",
        "exps.default": "supposée",
        "exps.published": "publiée",
        "src.trivy": "scan des paquets",
        "src.dnf-updateinfo": "mises à jour dnf",
        "src.openvas": "scan réseau",
        "src.external-scan": "scan externe",
        "src.inventory": "déclaré",
        "src.detected": "détecté ({sources})",
        "src.declared": "déclaré",
        "src.watchlist": "liste de surveillance",
        "src.cited": "produit cité par {source}",
        "label.exposed": "exposé à Internet",
        "label.not_exposed": "non exposé à Internet",
        "label.exposed_assumed": "exposé à Internet (hypothèse : exposition non déclarée)",
        "w.av.N": "Réseau",
        "w.av.A": "Réseau adjacent",
        "w.av.L": "Local",
        "w.av.P": "Physique",
        "w.ac.L": "Faible",
        "w.ac.H": "Élevée",
        "w.pr.N": "Aucun",
        "w.pr.L": "Authentification utilisateur simple",
        "w.pr.H": "Privilèges élevés",
        "w.ui.N": "Non",
        "w.ui.R": "Oui",
        "w.ui.P": "Oui (passive)",
        "w.ui.A": "Oui (active)",
        "w.risk.c": "Atteinte à la confidentialité des données",
        "w.risk.i": "Atteinte à l'intégrité des données",
        "w.risk.a": "Déni de service",
        "w.yes": "Oui",
        "w.no": "Non",
        "w.unspecified": "Non précisé",
        "w.unpublished": "non publié",
        "the_source": "la source",
    },
}
HEADINGS = ("h.why", "h.assets", "h.cve", "h.product", "h.type", "h.cvss", "h.impact", "h.exploitation",
            "h.description", "h.delay", "h.links")  # fmt: skip
TABLE = ("t.asset", "t.zone", "t.exposure", "t.installed", "t.fixed", "t.owner", "t.source")
NAMES = {"en": "English", "fr": "French", "de": "German", "es": "Spanish", "it": "Italian", "nl": "Dutch",
         "pt": "Portuguese"}  # fmt: skip


def known(lang: str) -> bool:
    return lang in LABELS


def t(lang: str, key: str, **kw: object) -> str:
    """The label `key` in `lang` (English when the language or the key is missing), formatted."""
    text = LABELS.get(lang, LABELS[DEFAULT]).get(key) or LABELS[DEFAULT][key]
    return text.format(**kw) if kw else text


def name(lang: str) -> str:
    return NAMES.get(lang, lang)


def heading_key(heading: str) -> str | None:
    """The catalogue key of a heading written in any language of the catalogue."""
    for labels in LABELS.values():
        for key in HEADINGS:
            if labels[key] == heading.strip():
                return key
    return None


def table_header(lang: str) -> list[str]:
    return ["| " + " | ".join(t(lang, k) for k in TABLE) + " |", "| " + " | ".join("---" for _ in TABLE) + " |"]


def reason(lang: str, code: str) -> str:
    """A reason of the watch (`kev`, `source:<name>`...) as a sentence of `lang`."""
    kind, _, arg = code.partition(":")
    return t(lang, f"reason.{kind}", source=arg) if kind == "source" else t(lang, f"reason.{kind}")


def check() -> list[str]:
    """Keys missing from a language of the catalogue (a test keeps it empty)."""
    ref = set(LABELS[DEFAULT])
    return [f"{lang}: {k}" for lang, labels in LABELS.items() for k in sorted(ref - set(labels))]
