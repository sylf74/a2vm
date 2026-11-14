# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""A local copy of OSV for the language ecosystems (v0.23.12, HLD D20): no inventory leaves the tenant.

OSV publishes its whole database, one archive per ecosystem (`<Ecosystem>/all.zip` on
osv-vulnerabilities.storage.googleapis.com). `build_index` reads an archive and keeps what NGVM
decides on: the records with a CVE (the record's id or an alias), not withdrawn, and for each package
the versions affected (the list OSV enumerates) and the ranges. `match` says whether a version of a
package is in it. The index is a gzipped JSON, a few megabytes per ecosystem: the shared
intelligence service builds it every few hours and serves it to the tenants (`GET
/v1/osv/<ecosystem>`), or a tenant without the shared service builds it from the archive itself.
Either way only the archive, the same for everyone, crosses the network: the tenant's libraries are
matched where they are.

How a version is decided, in order:

1. it is in the versions OSV enumerates for the package: affected;
2. else a range `SEMVER` (npm, Go, crates.io…): compared by semantic version;
3. else a range `ECOSYSTEM` without enumerated versions: compared by `compare` (numbers, then the
   pre-release markers before the release), a close reading of PEP 440 and of Maven's order for the
   usual versions;
4. a range `GIT` only: undecided (counted, not kept).
"""

from __future__ import annotations

import gzip
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import unquote

ARCHIVE = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
# purl type -> OSV ecosystem (the language ecosystems; the distributions go through ngvm.packages)
ECOSYSTEMS = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "nuget": "NuGet",
    "composer": "Packagist",
}
DEFAULT_ECOSYSTEMS = list(ECOSYSTEMS.values())
CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
PURL = re.compile(r"^pkg:(?P<type>[a-z0-9.+-]+)/(?P<path>[^@?#]+)@(?P<version>[^?#]+)")
INDEX_VERSION = 1


class OsvDbError(RuntimeError):
    pass


def name_key(ecosystem: str, name: str) -> str:
    """The package's name as OSV and a purl both say it."""
    name = name.strip()
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("Maven", "Go", "npm"):
        return name
    return name.lower()


def from_purl(purl: str) -> tuple[str, str, str] | None:
    """(ecosystem, name key, version) of a library's purl, or None outside the ecosystems known."""
    m = PURL.match(purl or "")
    if not m or m["type"] not in ECOSYSTEMS:
        return None
    eco = ECOSYSTEMS[m["type"]]
    parts = [unquote(p) for p in m["path"].split("/") if p]
    version = unquote(m["version"])
    if eco == "Maven":
        if len(parts) < 2:
            return None
        name = f"{parts[-2]}:{parts[-1]}"
    elif eco in ("npm", "Go", "Packagist"):
        name = "/".join(parts)
    else:
        name = parts[-1]
    if eco == "Go":
        version = version.removeprefix("v")
    return eco, name_key(eco, name), version


# -- versions -------------------------------------------------------------------------------------
_PRE = {"dev": -5, "snapshot": -5, "a": -4, "alpha": -4, "b": -3, "beta": -3, "m": -2, "milestone": -2,
        "c": -1, "rc": -1, "cr": -1, "pre": -1, "preview": -1}  # fmt: skip
_POST = {"post": 1, "sp": 1, "patch": 1, "final": 0, "ga": 0, "release": 0}


def _tokens(version: str) -> list[tuple[int, int | str]]:
    """A version as comparable tokens: (0, number) for a number, (rank, '') for a known marker
    (pre-releases below 0), (2, text) for any other word."""
    v = version.strip().lower().removeprefix("v").split("+", 1)[0]
    out: list[tuple[int, int | str]] = []
    for t in re.findall(r"\d+|[a-z]+", v):
        if t.isdigit():
            out.append((0, int(t)))
        elif t in _PRE:
            out.append((_PRE[t], ""))
        elif t in _POST:
            if _POST[t]:
                out.append((_POST[t], ""))
        else:
            out.append((2, t))
    while out and out[-1] == (0, 0):  # 1.0.0 == 1
        out.pop()
    return out


def compare(a: str, b: str) -> int:
    """-1, 0 or 1. Numbers in order, a pre-release (`rc1`, `-beta`, `.dev0`, `-SNAPSHOT`) before
    its release, a post-release after it."""
    ta, tb = _tokens(a), _tokens(b)
    for i in range(max(len(ta), len(tb))):
        x = ta[i] if i < len(ta) else (0, 0)
        y = tb[i] if i < len(tb) else (0, 0)
        if x == y:
            continue
        if x[0] == y[0] == 0:
            return -1 if x[1] < y[1] else 1  # type: ignore[operator]
        if x[0] == y[0] == 2:
            return -1 if str(x[1]) < str(y[1]) else 1
        # a pre-release marker (rank < 0) is below a missing token and a number; a word above
        rx = x[0] if x[0] != 0 else 0.5
        ry = y[0] if y[0] != 0 else 0.5
        return -1 if rx < ry else 1
    return 0


def _semver(v: str) -> tuple[tuple[int, ...], tuple[Any, ...]]:
    v = v.strip().removeprefix("v").split("+", 1)[0]
    core, _, pre = v.partition("-")
    nums = tuple(int(x) if x.isdigit() else 0 for x in (core.split(".") + ["0", "0"])[:3])
    if not pre:
        return nums, (1,)
    ids = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return nums, (0, ids)


def semver_compare(a: str, b: str) -> int:
    x, y = _semver(a), _semver(b)
    return (x > y) - (x < y)


def in_ranges(version: str, ranges: list[list[str]]) -> tuple[bool, str] | None:
    """(affected, fixed version) by the ranges, or None when no range decides (GIT only)."""
    decided = False
    for kind, introduced, fixed, last in ranges:
        if kind not in ("SEMVER", "ECOSYSTEM"):
            continue
        decided = True
        cmp = semver_compare if kind == "SEMVER" else compare
        if introduced not in ("", "0") and cmp(version, introduced) < 0:
            continue
        if fixed and cmp(version, fixed) >= 0:
            continue
        if last and cmp(version, last) > 0:
            continue
        return True, fixed
    return (False, "") if decided else None


# -- the index ------------------------------------------------------------------------------------
def _ranges(affected: dict[str, Any]) -> list[list[str]]:
    """Each range of an affected block as [type, introduced, fixed, last_affected], one per
    introduced event (OSV's events: introduced, then fixed or last_affected or limit)."""
    out = []
    for r in affected.get("ranges") or []:
        kind = str(r.get("type") or "")
        current: list[str] | None = None
        for e in r.get("events") or []:
            if "introduced" in e:
                if current:
                    out.append(current)
                current = [kind, str(e["introduced"]), "", ""]
            elif current and "fixed" in e:
                current[2] = str(e["fixed"])
                out.append(current)
                current = None
            elif current and "last_affected" in e:
                current[3] = str(e["last_affected"])
                out.append(current)
                current = None
        if current:
            out.append(current)
    return out


def index_record(rec: dict[str, Any], ecosystem: str, packages: dict[str, list[list[Any]]]) -> bool:
    """Add one OSV record to the packages of the index; False when it has no CVE or is withdrawn."""
    if rec.get("withdrawn"):
        return False
    cves = sorted({a for a in [rec.get("id", ""), *(rec.get("aliases") or [])] if CVE.match(str(a))})
    if not cves:
        return False
    rid = str(rec.get("id", ""))[:80]
    added = False
    for a in rec.get("affected") or []:
        pkg = a.get("package") or {}
        if str(pkg.get("ecosystem", "")).split(":", 1)[0] != ecosystem or not pkg.get("name"):
            continue
        versions = sorted({str(v) for v in a.get("versions") or []})
        ranges = _ranges(a)
        if not versions and not ranges:
            continue
        packages.setdefault(name_key(ecosystem, str(pkg["name"])), []).append([rid, cves, versions, ranges])
        added = True
    return added


def build_index(archive: BinaryIO | bytes | str | Path, ecosystem: str, built: str = "") -> dict[str, Any]:
    """The index of one ecosystem from OSV's all.zip (a file, a path or its bytes)."""
    source = io.BytesIO(archive) if isinstance(archive, bytes) else archive
    packages: dict[str, list[list[Any]]] = {}
    records = kept = 0
    try:
        with zipfile.ZipFile(source) as z:
            for info in z.infolist():
                if not info.filename.endswith(".json"):
                    continue
                records += 1
                try:
                    rec = json.loads(z.read(info))
                except ValueError:
                    continue
                kept += index_record(rec, ecosystem, packages)
    except zipfile.BadZipFile as exc:
        raise OsvDbError(f"{ecosystem}: not an OSV archive: {exc}") from exc
    return {"version": INDEX_VERSION, "ecosystem": ecosystem, "built": built, "records": records,
            "kept": kept, "packages": packages}  # fmt: skip


def dump_index(index: dict[str, Any]) -> bytes:
    return gzip.compress(json.dumps(index, separators=(",", ":")).encode("utf-8"), mtime=0)


def load_index(data: bytes) -> dict[str, Any]:
    try:
        index = json.loads(gzip.decompress(data))
    except (OSError, ValueError) as exc:
        raise OsvDbError(f"OSV index unreadable: {exc}") from exc
    if not isinstance(index, dict) or index.get("version") != INDEX_VERSION or "packages" not in index:
        raise OsvDbError("OSV index of another version")
    return index


def match(index: dict[str, Any], name: str, version: str) -> tuple[list[tuple[str, list[str], str]], int]:
    """([(record id, CVEs, fixed version)] affecting this version, records undecided)."""
    found, undecided = [], 0
    for rid, cves, versions, ranges in index["packages"].get(name, []):
        if version in versions:
            fixed = next((r[2] for r in ranges if r[2]), "")
            found.append((rid, cves, fixed))
            continue
        if versions and any(r[0] == "ECOSYSTEM" for r in ranges):
            continue  # OSV enumerated the versions of these ranges: not among them
        decided = in_ranges(version, ranges)
        if decided is None:
            undecided += 1
        elif decided[0]:
            found.append((rid, cves, decided[1]))
    return found, undecided


# -- the copy on disk -----------------------------------------------------------------------------
class OsvMirror:
    """The indexes of the ecosystems in a directory: `<Ecosystem>.json.gz` and its `.meta.json`
    (the archive's ETag, when it was built, how many records kept)."""

    def __init__(self, root: str | Path):
        self.root = Path(root)

    def path(self, ecosystem: str) -> Path:
        if ecosystem not in DEFAULT_ECOSYSTEMS:
            raise OsvDbError(f"unknown ecosystem {ecosystem!r}")
        return self.root / f"{ecosystem}.json.gz"

    def meta(self, ecosystem: str) -> dict[str, Any]:
        p = self.path(ecosystem).with_suffix(".meta.json")
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def save(self, ecosystem: str, data: bytes, meta: dict[str, Any]) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.path(ecosystem)
        tmp = path.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(path)
        path.with_suffix(".meta.json").write_text(json.dumps(meta), encoding="utf-8")

    def load(self, ecosystem: str) -> dict[str, Any] | None:
        path = self.path(ecosystem)
        return load_index(path.read_bytes()) if path.exists() else None

    def refresh(self, ecosystem: str, client: Any, now: str = "", url: str = ARCHIVE) -> str:
        """Download OSV's archive of the ecosystem when it changed (ETag) and rebuild its index.
        `client` is an httpx.Client (the proxy, the relay of the sources). Returns a line for the log."""
        import httpx

        meta = self.meta(ecosystem)
        headers = {"If-None-Match": meta["etag"]} if meta.get("etag") and self.path(ecosystem).exists() else {}
        self.root.mkdir(parents=True, exist_ok=True)
        tmp = self.root / f".{ecosystem}.zip"
        try:
            with client.stream("GET", url.format(ecosystem=ecosystem), headers=headers) as r:
                if r.status_code == 304:
                    return f"osv {ecosystem}: unchanged ({meta.get('kept', 0)} records with a CVE)"
                if r.status_code >= 400:
                    raise OsvDbError(f"osv {ecosystem}: HTTP {r.status_code}")
                with tmp.open("wb") as f:
                    for chunk in r.iter_bytes(1 << 20):
                        f.write(chunk)
                etag = r.headers.get("ETag", "")
            index = build_index(tmp, ecosystem, now)
        except httpx.HTTPError as exc:
            raise OsvDbError(f"osv {ecosystem}: {exc}") from exc
        finally:
            tmp.unlink(missing_ok=True)
        self.save(ecosystem, dump_index(index), {"etag": etag, "built": now, "records": index["records"],
                                                 "kept": index["kept"]})  # fmt: skip
        return f"osv {ecosystem}: {index['records']} records, {index['kept']} with a CVE"
