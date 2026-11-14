# SPDX-License-Identifier: LicenseRef-a2vm-proprietary
"""The asset graph of a client (v0.24.0) and the exposure computed from it.

The assets stage builds, next to the inventory, a graph of how its assets are reached: nodes for the
internet, the zones, the assets (hosts, images, declared assets), their network services and the
public endpoints of `published`; edges for what is declared (a zone, a flow, a `published` entry)
and what is observed (a port a scanner reached from a zone, a socket a host listens on, a machine
seen off the premises). Each edge says where it comes from and when it was seen.

The exposure of an asset (SSVC System Exposure) is then computed from it, and the path it rests on
is kept as its proof (`Asset.exposure_path`):

- open: the external scan reached the asset (directly or behind a `published` endpoint); the asset
  was seen off the premises within `off_premises_days`; it sits in a zone declared `open`; or a flow
  declared from the internet reaches its zone on a port it serves;
- small: a source listed the sockets of the host and none listens beyond its loopback, and no
  scanner reached it;
- controlled: a scanner reached it from a zone, or it listens on the network, or a declared flow
  reaches its zone, and the external scan (recent) did not reach it;
- otherwise the default: the client's default assumption when the external scan is recent or when
  the client has none (gap `no-external-scan`); the worst case, open, when the client has an external
  scan but none recent in this run.

Precedence: what is observed comes first. The external scan and a machine seen off the premises
raise the exposure whatever was declared; an exposure declared for the asset (profile, CMDB, rule)
comes before what the graph derives from declared zones and flows; the graph replaces only an
assumed value. A declaration the observations contradict stays, with its state in `checks` and a gap.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from a2vm.models import INTERNET, OFF_PREMISES, Asset, AssetObservation, Attribute, ClientProfile

SCHEMA = "a2vm.asset_graph/1"
GRAPH = "graph"  # the source of an exposure computed from the graph
EXTERNAL = "external-scan"
# Sources whose addresses do not say where a machine is: the CMDB (an inventory), the external scan
# (public addresses), the network scanner (it reached the machine, so it is on the premises) and the
# declared inventory.
NOT_WHERE = {"cmdb", EXTERNAL, "openvas", "inventory"}

NODE_KINDS = ("internet", "zone", "endpoint", "host", "image", "declared", "service", "process", "component")
EDGE_KINDS = ("member_of", "flow", "publishes", "routes_to", "reaches", "listens", "runs_on")


@dataclass
class Node:
    id: str
    kind: str
    label: str
    attrs: dict[str, Any] = field(default_factory=dict)


@dataclass
class Edge:
    source: str
    target: str
    kind: str
    evidence: str  # declared | observed
    origin: str = ""  # the profile section, the rule or the scanner it comes from
    seen: str = ""  # when it was observed (observed edges)
    port: str = ""  # 443/tcp, for flows and reaches
    note: str = ""


@dataclass
class AssetGraph:
    client_id: str
    generated_at: str
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)
    # asset id -> {value, source, note, path}: the exposure and what it rests on
    exposure: dict[str, dict[str, Any]] = field(default_factory=dict)
    flows: list[dict[str, Any]] = field(default_factory=list)  # the declared flows and their state
    observed_flows: list[dict[str, Any]] = field(default_factory=list)  # zone -> zone, port, assets
    checks: list[dict[str, str]] = field(default_factory=list)  # declared exposures: confirmed, contradicted...
    off_premises: dict[str, str] = field(default_factory=dict)  # asset id -> last seen off the premises
    external_scan: str = ""  # date of the newest external observation of the run, "" without
    _keys: set[tuple[str, ...]] = field(default_factory=set, repr=False, compare=False)

    def node(self, node_id: str, kind: str, label: str, **attrs: Any) -> Node:
        found = self.nodes.get(node_id)
        if found is None:
            found = self.nodes[node_id] = Node(node_id, kind, label, dict(attrs))
        return found

    def edge(self, source: str, target: str, kind: str, evidence: str, **kw: str) -> Edge:
        e = Edge(source, target, kind, evidence, **kw)
        key = (source, target, kind, e.port, e.origin)
        if key not in self._keys:  # the same edge twice (an endpoint in front of several assets): once
            self._keys.add(key)
            self.edges.append(e)
        return e

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "client_id": self.client_id,
            "generated_at": self.generated_at,
            "external_scan": self.external_scan,
            "nodes": [asdict(n) for n in sorted(self.nodes.values(), key=lambda n: (n.kind, n.id))],
            "edges": [asdict(e) for e in self.edges],
            "exposure": dict(sorted(self.exposure.items())),
            "flows": self.flows,
            "observed_flows": self.observed_flows,
            "checks": self.checks,
            "off_premises": dict(sorted(self.off_premises.items())),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssetGraph:
        g = cls(data["client_id"], data.get("generated_at", ""))
        g.nodes = {n["id"]: Node(**n) for n in data.get("nodes") or []}
        for e in data.get("edges") or []:
            g.edge(**e)
        g.exposure = dict(data.get("exposure") or {})
        g.flows = list(data.get("flows") or [])
        g.observed_flows = list(data.get("observed_flows") or [])
        g.checks = list(data.get("checks") or [])
        g.off_premises = dict(data.get("off_premises") or {})
        g.external_scan = data.get("external_scan", "")
        return g


def write_graph(path: str | Path, graph: AssetGraph) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(graph.to_dict(), ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    return path


def read_graph(path: str | Path, client_id: str) -> AssetGraph | None:
    """The graph of `client_id`; None when the file is absent (assets built before v0.24.0)."""
    path = Path(path)
    if not path.exists():
        return None
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("schema") != SCHEMA or data.get("client_id") != client_id:
        raise ValueError(f"{path}: not the asset graph of {client_id!r}")
    return AssetGraph.from_dict(data)


# -- zones -----------------------------------------------------------------------------------------
class Zones:
    """The zones of the profile and the networks that place an address in one (longest prefix)."""

    def __init__(self, profile: ClientProfile):
        self.declared = {z.id: z for z in profile.zones}
        nets = [(ipaddress.ip_network(n, strict=False), z.id) for z in profile.zones for n in z.networks]
        self.networks = sorted(nets, key=lambda x: -x[0].prefixlen)

    @property
    def has_networks(self) -> bool:
        return bool(self.networks)

    def of_address(self, address: str) -> tuple[str, str] | None:
        """(zone id, network) of an address; None when no declared network holds it."""
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return None
        for net, zone in self.networks:
            if ip.version == net.version and ip in net:
                return zone, str(net)
        return None

    def of_addresses(self, addresses: list[str]) -> tuple[str, str] | None:
        return next((z for z in (self.of_address(a) for a in addresses) if z), None)

    def is_open(self, zone: str) -> bool:
        return zone == OFF_PREMISES or bool(self.declared.get(zone) and self.declared[zone].open)


def zone_from_networks(zones: Zones, ids: dict[str, Any]) -> Attribute | None:
    found = zones.of_addresses(list(ids.get("ips") or []))
    return Attribute(found[0], "networks", found[1]) if found else None


# -- services --------------------------------------------------------------------------------------
def consolidate_services(group: list[AssetObservation]) -> list[dict[str, str]]:
    """The services of one asset: every source's, newest sighting of each, with source and date."""
    out: dict[tuple[str, ...], dict[str, str]] = {}
    for o in group:
        for s in o.services or []:
            item = {k: v for k, v in s.items() if v not in (None, "")}
            item.update(source=o.source, seen=o.observed_at)
            key = (item["port"], item["view"], item.get("from_zone", ""), item.get("bind", ""), o.source)
            if key not in out or o.observed_at > out[key]["seen"]:
                out[key] = item
    return [out[k] for k in sorted(out, key=lambda k: (_port_number(k[0]), k))]


def _port_number(port: str) -> int:
    head = port.split("/", 1)[0]
    return int(head) if head.isdigit() else 0


def listed_locally(group: list[AssetObservation]) -> bool:
    """A source listed the sockets of the host (services not None, view local or an empty list)."""
    return any(o.services is not None and o.source not in NOT_WHERE for o in group)


# -- off the premises ------------------------------------------------------------------------------
def off_premises_sighting(zones: Zones, group: list[AssetObservation]) -> str:
    """When a source last saw the machine with only addresses outside every declared network; ""."""
    if not zones.has_networks:
        return ""
    seen = ""
    for o in group:
        if o.kind != "host" or o.source in NOT_WHERE:
            continue
        ips = list(o.identifiers.get("ips") or [])
        if ips and zones.of_addresses(ips) is None:
            seen = max(seen, o.observed_at)
    return seen


def _parse(ts: str) -> dt.datetime | None:
    try:
        value = dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.UTC)


def within(ts: str, days: int, now: dt.datetime) -> bool:
    when = _parse(ts) if ts else None
    return when is not None and now - when <= dt.timedelta(days=days)


# -- the graph and the exposure --------------------------------------------------------------------
@dataclass
class AssetFacts:
    """What the assets stage knows of one asset for the graph."""

    asset: Asset
    group: list[AssetObservation]
    endpoint: str = ""  # the public endpoint (or addresses) the external scan reached it at
    front: str = ""  # the asset id of the published asset it is reached behind, "" when direct
    published: bool = False  # the endpoint is a `published` entry (else an address nobody declared)
    off_premises: str = ""  # last sighting off the premises in this run


def _label(asset: Asset) -> str:
    return asset.name or asset.id


def _step(graph: AssetGraph, node_id: str, via: str = "", source: str = "", seen: str = "") -> dict[str, str]:
    n = graph.nodes[node_id]
    step = {"node": node_id, "kind": n.kind, "label": n.label}
    if via:
        step["via"] = via
    if source:
        step["source"] = source
    if seen:
        step["seen"] = seen
    return step


def _network_services(asset: Asset) -> list[dict[str, str]]:
    return [s for s in asset.services if s["view"] == "network"]


def _listening(asset: Asset) -> list[dict[str, str]]:
    return [s for s in asset.services if s["view"] == "local" and s.get("bind") not in ("loopback", "")]


def _serves(asset: Asset, port: str | None) -> bool | None:
    """Whether the asset serves a port: None when its ports are not known."""
    ports = {s["port"] for s in _network_services(asset) + _listening(asset)}
    if not ports:
        return None
    return port is None or port in ports


def build_graph(
    profile: ClientProfile,
    facts: list[AssetFacts],
    generated_at: str,
    previous: AssetGraph | None = None,
    now: dt.datetime | None = None,
) -> tuple[AssetGraph, list[dict[str, str]]]:
    """The graph of the client, the exposure of each asset set from it (in place, path included), and
    the exposure gaps it finds (declared-not-open, declared-small-but-reachable, undeclared-flow,
    no-external-scan). Images are left to inherit from their host afterwards."""
    now = now or dt.datetime.now(dt.UTC)
    zones = Zones(profile)
    graph = AssetGraph(profile.id, generated_at)
    gaps: list[dict[str, str]] = []
    graph.node(INTERNET, "internet", "internet")
    for z in profile.zones:
        graph.node(f"zone:{z.id}", "zone", z.id, declared=True, open=z.open, networks=list(z.networks))
    graph.node(f"zone:{OFF_PREMISES}", "zone", OFF_PREMISES, declared=False, open=True)
    externals = [o.observed_at for f in facts for o in f.group if o.source == EXTERNAL]
    graph.external_scan = max(externals, default="")
    recent_external = profile.external is not None and bool(graph.external_scan)

    def zone_node(zone: str) -> str:
        return graph.node(f"zone:{zone}", "zone", zone, declared=zone in zones.declared).id

    for i, flow in enumerate(profile.flows):
        src = INTERNET if flow.source == INTERNET else zone_node(flow.source) if flow.source != "*" else "zone:*"
        dst = zone_node(flow.target) if flow.target != "*" else "zone:*"
        if "zone:*" in (src, dst):
            graph.node("zone:*", "zone", "*", declared=True)
        for port in flow.ports or [""]:
            graph.edge(src, dst, "flow", "declared", origin=f"flows/{i}", port=port, note=flow.description)
        graph.flows.append(
            {"from": flow.source, "to": flow.target, "ports": list(flow.ports), "state": "unverified", "seen": ""}
        )

    by_id = {f.asset.id: f for f in facts}
    for f in facts:
        a = f.asset
        graph.node(a.id, a.kind, _label(a))
        zone = a.attributes.get("zone")
        if zone is not None:
            evidence = "observed" if zone.source == "networks" else "declared"
            origin = f"{zone.source} ({zone.note})" if zone.note else zone.source
            graph.edge(a.id, zone_node(zone.value), "member_of", evidence, origin=origin)
        listed: set[str] = set()
        for s in a.services:
            sid = f"service:{a.id}:{s['port']}"
            graph.node(sid, "service", f"{_label(a)} {s['port']}", port=s["port"])
            if sid not in listed:
                listed.add(sid)
                graph.edge(a.id, sid, "listens", "observed", origin=s["source"], seen=s["seen"], port=s["port"])
            if s["view"] == "network":
                src = (
                    INTERNET
                    if s.get("from_zone") == INTERNET
                    else zone_node(s["from_zone"])
                    if s.get("from_zone")
                    else ""
                )
                if src:
                    graph.edge(src, sid, "reaches", "observed", origin=s["source"], seen=s["seen"], port=s["port"])
        if f.endpoint:
            eid = f"endpoint:{f.endpoint}"
            graph.node(eid, "endpoint", f.endpoint)
            seen = max((o.observed_at for o in by_id.get(f.front or a.id, f).group if o.source == EXTERNAL), default="")
            graph.edge(INTERNET, eid, "publishes", "observed", origin=EXTERNAL, seen=seen)
            graph.edge(eid, f.front or a.id, "publishes", "declared" if f.published else "observed",
                       origin="published" if f.published else EXTERNAL)  # fmt: skip
            if f.front:
                graph.edge(f.front, a.id, "routes_to", "declared", origin="published (behind)")
        last = max(f.off_premises, (previous.off_premises.get(a.id, "") if previous else ""))
        if last and within(last, profile.off_premises_days, now):
            graph.off_premises[a.id] = last
            graph.edge(a.id, f"zone:{OFF_PREMISES}", "member_of", "observed", origin="addresses", seen=last)

    observed: dict[tuple[str, str, str], list[str]] = {}
    for f in facts:
        exposure, gap = _exposure(graph, profile, zones, f, by_id, recent_external)
        f.asset.attributes["exposure"] = exposure["attribute"]
        f.asset.exposure_path = exposure["path"]
        graph.exposure[f.asset.id] = {
            "value": exposure["attribute"].value,
            "source": exposure["attribute"].source,
            "note": exposure["attribute"].note,
            "path": exposure["path"],
        }
        if exposure.get("check"):
            graph.checks.append(exposure["check"])
        if gap:
            gaps.append(gap)
        zone = f.asset.attributes.get("zone")
        for s in _network_services(f.asset):
            source = s.get("from_zone", "")
            if source and zone is not None and source != zone.value:
                observed.setdefault((source, zone.value, s["port"]), []).append(f.asset.id)

    for (source, target, port), assets in sorted(observed.items()):
        allowed = [i for i, fl in enumerate(profile.flows) if fl.allows(source, target, port)]
        for i in allowed:
            graph.flows[i]["state"] = "confirmed"
        graph.observed_flows.append(
            {"from": source, "to": target, "port": port, "assets": sorted(set(assets)), "declared": bool(allowed)}
        )
        if profile.flows and not allowed:
            names = sorted({by_id[a].asset.name for a in assets})
            gaps.append(
                {
                    "kind": "undeclared-flow",
                    "asset": sorted(set(assets))[0],
                    "name": f"{source} -> {target} {port}",
                    "detail": f"{len(names)} asset(s) reached from {source} on {port}, allowed by no flow: "
                    + ", ".join(names[:10])
                    + (", ..." if len(names) > 10 else ""),
                }
            )
    if profile.external is None and any(
        f.asset.kind != "image" and f.asset.attributes["exposure"].source == "default" for f in facts
    ):
        gaps.append(
            {
                "kind": "no-external-scan",
                "asset": "",
                "name": profile.id,
                "detail": "no external scan: the exposure without proof is the client's default assumption, "
                "with nothing to check it against",
            }
        )
    return graph, gaps


def _open_zone(zones: Zones, zone: Attribute | None) -> bool:
    return zone is not None and zones.is_open(zone.value)


def _internet_flow(profile: ClientProfile, zone: Attribute | None, asset: Asset) -> tuple[int, str] | None:
    """(flow index, port) of a flow declared from the internet to the asset's zone on a port it serves."""
    if zone is None:
        return None
    for i, flow in enumerate(profile.flows):
        if flow.source != INTERNET or flow.target not in ("*", zone.value):
            continue
        for port in flow.ports or [None]:
            if _serves(asset, port) is not False:
                return i, port or ""
    return None


def _inbound_flow(profile: ClientProfile, zone: Attribute | None) -> int | None:
    if zone is None:
        return None
    return next(
        (
            i
            for i, fl in enumerate(profile.flows)
            if fl.source != INTERNET and fl.target in ("*", zone.value) and fl.source != zone.value
        ),
        None,
    )


def _exposure(
    graph: AssetGraph,
    profile: ClientProfile,
    zones: Zones,
    f: AssetFacts,
    by_id: dict[str, AssetFacts],
    recent_external: bool,
) -> tuple[dict[str, Any], dict[str, str] | None]:
    a = f.asset
    current = a.attributes["exposure"]
    zone = a.attributes.get("zone")
    zid = f"zone:{zone.value}" if zone is not None else ""
    declared = current.source in ("declared", "cmdb", "rule")
    out: dict[str, Any] = {"attribute": current, "path": []}

    # 1. The external scan reached it: open, observed (set by the assets stage).
    if current.source == EXTERNAL:
        eid = f"endpoint:{f.endpoint}"
        seen = next((e.seen for e in graph.edges if e.source == INTERNET and e.target == eid), "")
        out["path"] = [_step(graph, INTERNET), _step(graph, eid, "publishes", EXTERNAL, seen)]
        if f.front:
            out["path"] += [
                _step(graph, f.front, "publishes", "published"),
                _step(graph, a.id, "routes_to", "published"),
            ]
        else:
            out["path"].append(_step(graph, a.id, "publishes", "published" if f.published else EXTERNAL))
        return out, None

    # 2. Seen off the premises within the window: open, observed; it wins over a declaration.
    last = graph.off_premises.get(a.id)
    if last:
        oz = f"zone:{OFF_PREMISES}"
        out["attribute"] = Attribute("open", GRAPH, f"seen off the premises on {last[:10]}")
        out["path"] = [
            _step(graph, INTERNET),
            _step(graph, oz, "member_of"),
            _step(graph, a.id, "member_of", "addresses", last),
        ]
        gap = None
        if declared and current.value != "open":
            out["check"] = _check(a, current, "contradicted", out["attribute"].note)
            gap = {
                "kind": "declared-not-open",
                "asset": a.id,
                "name": a.name,
                "declared": current.value,
                "detail": f"{current.source} {current.value}, but {out['attribute'].note}",
            }
        return out, gap

    reach = [s for s in _network_services(a) if s.get("from_zone") != INTERNET]
    listening = _listening(a)
    inbound = _inbound_flow(profile, zone)

    # 3. An exposure declared for the asset stands; observations may contradict it.
    if current.source != "default":
        if current.value == "small" and (reach or listening):
            seen = (reach or listening)[0]
            how = f"{seen['source']} saw {seen['port']} " + ("reached" if reach else "listening")
            out["check"] = _check(a, current, "contradicted", how)
            return out, {
                "kind": "declared-small-but-reachable",
                "asset": a.id,
                "name": a.name,
                "declared": current.value,
                "detail": f"{current.source} small, but {how}",
            }
        if declared:
            state = "confirmed" if (current.value == "controlled" and (reach or listening)) else "unverified"
            out["check"] = _check(a, current, state, "")
        return out, None

    # 4. Assumed: the graph decides when it can.
    if _open_zone(zones, zone):
        out["attribute"] = Attribute("open", GRAPH, f"in zone {zone.value}, declared open")
        out["path"] = [
            _step(graph, INTERNET),
            _step(graph, zid, "member_of"),
            _step(graph, a.id, "member_of", zone.source),
        ]
        return out, None
    flow = _internet_flow(profile, zone, a)
    if flow is not None:
        i, port = flow
        on = f" on {port}" if port else ""
        out["attribute"] = Attribute("open", GRAPH, f"flow from the internet to zone {zone.value}{on} (flows/{i})")
        out["path"] = [_step(graph, INTERNET), _step(graph, zid, "flow", f"flows/{i}")]
        sid = f"service:{a.id}:{port}"
        if port and sid in graph.nodes:
            out["path"].append(_step(graph, sid, "reaches"))
        out["path"].append(_step(graph, a.id, "member_of" if not port or sid not in graph.nodes else "listens"))
        return out, None
    if a.kind == "host" and listed_locally(f.group) and not listening and not _network_services(a):
        out["attribute"] = Attribute("small", GRAPH, "listens on its loopback only, reached by no scanner")
        out["path"] = [_step(graph, a.id)]
        return out, None
    if recent_external and (reach or listening or inbound is not None):
        ext = graph.external_scan[:10]
        if reach:
            s = reach[0]
            src = f"zone:{s['from_zone']}" if s.get("from_zone") else ""
            where = f"from zone {s['from_zone']}" if src else "by an internal scanner"
            note = f"reached {where} on {s['port']} ({s['source']}); not seen by the external scan of {ext}"
            sid = f"service:{a.id}:{s['port']}"
            out["path"] = ([_step(graph, src)] if src else []) + [
                _step(graph, sid, "reaches", s["source"], s["seen"]),
                _step(graph, a.id, "listens"),
            ]
        elif listening:
            s = listening[0]
            note = f"listens on {s['port']} ({s['source']}); not seen by the external scan of {ext}"
            out["path"] = [
                _step(graph, f"service:{a.id}:{s['port']}", "", s["source"], s["seen"]),
                _step(graph, a.id, "listens"),
            ]
        else:
            fl = profile.flows[inbound]
            note = (
                f"zone {zone.value} reached from {fl.source} (flows/{inbound}); not seen by the external scan of {ext}"
            )
            src = f"zone:{fl.source}" if fl.source != "*" else "zone:*"
            out["path"] = [
                _step(graph, src),
                _step(graph, zid, "flow", f"flows/{inbound}"),
                _step(graph, a.id, "member_of"),
            ]
        out["attribute"] = Attribute("controlled", GRAPH, note)
        return out, None
    if profile.external is not None and not recent_external and current.value != "open":
        out["attribute"] = Attribute("open", "default", "worst case: no recent external scan in this run")
    return out, None


def _check(asset: Asset, declared: Attribute, state: str, detail: str) -> dict[str, str]:
    out = {"asset": asset.id, "name": asset.name, "declared": declared.value, "source": declared.source, "state": state}
    if detail:
        out["detail"] = detail
    return out


def inherit_paths(assets: list[Asset]) -> None:
    """An image whose exposure comes from its host takes the host's path, then runs_on."""
    by_id = {a.id: a for a in assets}
    for a in assets:
        host = by_id.get(a.identifiers.get("runs_on", ""))
        if a.kind != "image" or host is None or a.attributes["exposure"].source != "host":
            continue
        a.exposure_path = [*host.exposure_path, {"node": a.id, "kind": "image", "label": a.name, "via": "runs_on"}]


def proposed_flows(graph: AssetGraph) -> str:
    """The flows the scanners observed, as a `flows:` section to review (v0.24.0): what is declared
    already is marked, what is not is proposed. YAML, ready to paste into client.yaml."""
    grouped: dict[tuple[str, str], dict[str, bool]] = {}
    for f in graph.observed_flows:
        grouped.setdefault((f["from"], f["to"]), {})[f["port"]] = f["declared"]
    lines = [
        f"# Flows observed by the scanners of {graph.client_id} ({graph.generated_at[:10]}): review, keep what is",
        "# intended, and fix the rest on the network rather than here.",
        "flows:",
    ]
    if not grouped:
        return "\n".join([*lines[:1], "# no flow between zones observed", "flows: []", ""])
    for (source, target), ports in sorted(grouped.items()):
        ordered = sorted(ports, key=lambda p: (_port_number(p), p))
        state = "declared" if all(ports.values()) else "not declared" if not any(ports.values()) else "partly declared"
        lines.append(f"  - from: {source}")
        lines.append(f"    to: {target}")
        lines.append(f"    ports: [{', '.join(ordered)}]")
        lines.append(f"    description: observed, {state}")
    return "\n".join(lines) + "\n"
