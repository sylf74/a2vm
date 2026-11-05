-- SPDX-License-Identifier: LicenseRef-a2vm-proprietary
-- Reporting database of A2VM (schema a2vm, version 5): the reporting datasets of every run and
-- tenant, read by dashboarding and reporting tools. Idempotent: run again on every init; an
-- upgrade only adds (columns, views, functions), so a database of an earlier version is kept.
-- Objects are owned by the writer role (the A2VM jobs); readers get SELECT, limited to their
-- tenants by row-level security (a2vm.tenant_roles).

CREATE SCHEMA IF NOT EXISTS a2vm;

CREATE TABLE IF NOT EXISTS a2vm.schema_version (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
INSERT INTO a2vm.schema_version (version) VALUES (1), (2), (3), (4), (5) ON CONFLICT DO NOTHING;

-- Which tenants a reading role may see; tenant '*' = all of them (the Grafana of the MSSP).
CREATE TABLE IF NOT EXISTS a2vm.tenant_roles (
    role   name NOT NULL,
    tenant text NOT NULL,
    PRIMARY KEY (role, tenant)
);

CREATE TABLE IF NOT EXISTS a2vm.runs (
    run_id          bigserial PRIMARY KEY,
    tenant          text NOT NULL,
    tenant_name     text NOT NULL,
    generated_at    timestamptz NOT NULL,
    published_at    timestamptz NOT NULL DEFAULT now(),
    a2vm_version    text NOT NULL,
    policy_hash     text NOT NULL,
    pipeline_id     text,
    pipeline_url    text,
    cve_count       integer NOT NULL,
    act             integer NOT NULL,
    attend          integer NOT NULL,
    track           integer NOT NULL,
    assets_act      integer NOT NULL,
    assets_attend   integer NOT NULL,
    assets_track    integer NOT NULL,
    needs_review    integer NOT NULL,
    assumed_inputs  integer NOT NULL,
    not_affected    integer NOT NULL,
    errors          integer NOT NULL,
    overdue         integer NOT NULL,
    due_soon        integer NOT NULL,
    exposure_gaps   integer NOT NULL,
    UNIQUE (tenant, generated_at)
);

CREATE TABLE IF NOT EXISTS a2vm.decisions (
    run_id          bigint NOT NULL REFERENCES a2vm.runs ON DELETE CASCADE,
    tenant          text NOT NULL,
    finding_id      text NOT NULL,
    asset           text NOT NULL,
    asset_name      text,
    zone            text,
    exposure        text,
    exposure_source text,
    cve             text NOT NULL,
    title           text,
    level           text NOT NULL CHECK (level IN ('ACT', 'ATTEND', 'TRACK')),
    ssvc            text,
    bod_timeline    text,
    first_seen      date,
    due_date        date,
    kev             boolean NOT NULL,
    epss            real,
    needs_review    boolean NOT NULL,
    rationale       text
);
CREATE INDEX IF NOT EXISTS decisions_run ON a2vm.decisions (run_id);
-- Version 2 (v0.11.6): what the per-asset and per-CVE dashboards filter on. Empty for runs
-- published before.
ALTER TABLE a2vm.decisions
    ADD COLUMN IF NOT EXISTS cvss_score    real,
    ADD COLUMN IF NOT EXISTS cvss_version  text,
    ADD COLUMN IF NOT EXISTS severity      text,
    ADD COLUMN IF NOT EXISTS fix_available boolean,
    ADD COLUMN IF NOT EXISTS vendor        text,
    ADD COLUMN IF NOT EXISTS product       text,
    ADD COLUMN IF NOT EXISTS product_type  text,
    ADD COLUMN IF NOT EXISTS sources       text[];

CREATE TABLE IF NOT EXISTS a2vm.assets (
    run_id   bigint NOT NULL REFERENCES a2vm.runs ON DELETE CASCADE,
    tenant   text NOT NULL,
    asset    text NOT NULL,
    name     text,
    zone     text,
    exposure text,
    owner    text,
    act      integer NOT NULL,
    attend   integer NOT NULL,
    track    integer NOT NULL
);
CREATE INDEX IF NOT EXISTS assets_run ON a2vm.assets (run_id);
-- Version 3 (v0.18.1): every asset of a run, a finding or not, with its scans; the last observation
-- of each finding per source. A finding gone from a run is told fixed from unchecked with them.
ALTER TABLE a2vm.assets
    ADD COLUMN IF NOT EXISTS kind      text,
    ADD COLUMN IF NOT EXISTS scans     jsonb,
    ADD COLUMN IF NOT EXISTS last_seen timestamptz;
ALTER TABLE a2vm.decisions ADD COLUMN IF NOT EXISTS seen_by jsonb;
CREATE INDEX IF NOT EXISTS decisions_run_finding ON a2vm.decisions (run_id, finding_id);

CREATE TABLE IF NOT EXISTS a2vm.exposure_gaps (
    run_id   bigint NOT NULL REFERENCES a2vm.runs ON DELETE CASCADE,
    tenant   text NOT NULL,
    kind     text NOT NULL,
    asset    text NOT NULL,
    name     text,
    declared text,
    detail   text
);

-- Version 4 (v0.19.0): the scan coverage of each host asset against the tenant's CMDB, and the
-- configuration item of each asset. Empty for runs published before.
ALTER TABLE a2vm.runs
    ADD COLUMN IF NOT EXISTS cmdb            boolean,
    ADD COLUMN IF NOT EXISTS expected_assets integer,
    ADD COLUMN IF NOT EXISTS covered_assets  integer,
    ADD COLUMN IF NOT EXISTS coverage_gaps   integer;
ALTER TABLE a2vm.assets
    ADD COLUMN IF NOT EXISTS cmdb_class  text,
    ADD COLUMN IF NOT EXISTS cmdb_status text,
    ADD COLUMN IF NOT EXISTS criticality text,
    ADD COLUMN IF NOT EXISTS coverage    text;
CREATE TABLE IF NOT EXISTS a2vm.coverage (
    run_id      bigint NOT NULL REFERENCES a2vm.runs ON DELETE CASCADE,
    tenant      text NOT NULL,
    asset       text NOT NULL,
    name        text,
    state       text NOT NULL,
    cmdb_class  text,
    cmdb_key    text,
    cmdb_status text,
    criticality text,
    cmdb_type   text,
    owner       text,
    expected    text[],
    missing     text[],
    scans       jsonb,
    last_scan   timestamptz
);
CREATE INDEX IF NOT EXISTS coverage_run ON a2vm.coverage (run_id);
-- Version 5 (v0.21.0, HLD D19): the priority of each decision in the client's SLA, the rule applied,
-- the day it entered that priority and its SLA due date (due_date stays the BOD 26-04 one, for
-- comparison); the SLA counts of each run. NULL for runs published before and clients without an SLA.
ALTER TABLE a2vm.decisions
    ADD COLUMN IF NOT EXISTS priority         text,
    ADD COLUMN IF NOT EXISTS priority_rank    integer,
    ADD COLUMN IF NOT EXISTS sla_rule         integer,
    ADD COLUMN IF NOT EXISTS sla_since        date,
    ADD COLUMN IF NOT EXISTS sla_due          date,
    ADD COLUMN IF NOT EXISTS sla_since_source text;
ALTER TABLE a2vm.runs
    ADD COLUMN IF NOT EXISTS sla_overdue      integer,
    ADD COLUMN IF NOT EXISTS sla_due_soon     integer,
    ADD COLUMN IF NOT EXISTS sla_unclassified integer;
CREATE TABLE IF NOT EXISTS a2vm.sources (
    run_id           bigint NOT NULL REFERENCES a2vm.runs ON DELETE CASCADE,
    tenant           text NOT NULL,
    name             text NOT NULL,
    findings         integer NOT NULL,
    last_observation timestamptz
);

ALTER TABLE a2vm.tenant_roles ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS own_rows ON a2vm.tenant_roles;
CREATE POLICY own_rows ON a2vm.tenant_roles FOR SELECT USING (role = current_user);

-- The latest run of each tenant, and its rows: what most panels show.
CREATE OR REPLACE VIEW a2vm.latest_runs AS
    SELECT DISTINCT ON (tenant) * FROM a2vm.runs ORDER BY tenant, generated_at DESC;
CREATE OR REPLACE VIEW a2vm.latest_decisions AS
    SELECT d.* FROM a2vm.decisions d JOIN a2vm.latest_runs r USING (run_id);
CREATE OR REPLACE VIEW a2vm.latest_assets AS
    SELECT a.* FROM a2vm.assets a JOIN a2vm.latest_runs r USING (run_id);
CREATE OR REPLACE VIEW a2vm.latest_exposure_gaps AS
    SELECT g.* FROM a2vm.exposure_gaps g JOIN a2vm.latest_runs r USING (run_id);

-- Row-level security: a reader sees the tenants a2vm.tenant_roles grants it; the owner (writer)
-- is not subject to it. The views run with the caller's rights (security_invoker).
ALTER VIEW a2vm.latest_runs SET (security_invoker = true);
ALTER VIEW a2vm.latest_decisions SET (security_invoker = true);
ALTER VIEW a2vm.latest_assets SET (security_invoker = true);
ALTER VIEW a2vm.latest_exposure_gaps SET (security_invoker = true);

-- Every decision with its run's date and the labels the dashboards filter on (version 2): the
-- dashboards group and filter, they compute no rule of their own.
CREATE OR REPLACE VIEW a2vm.decision_facts AS
    SELECT d.run_id, d.tenant, r.tenant_name, r.generated_at, r.generated_at::date AS day,
           d.finding_id, d.asset, coalesce(d.asset_name, d.asset) AS asset_name, d.zone, d.exposure,
           d.cve, d.title, d.level,
           CASE d.level WHEN 'ACT' THEN 1 WHEN 'ATTEND' THEN 2 ELSE 3 END AS level_rank,
           d.ssvc, d.bod_timeline, d.first_seen, d.due_date, d.kev, d.epss, d.needs_review,
           d.cvss_score, coalesce(d.severity, 'Unknown') AS severity,
           CASE coalesce(d.severity, 'Unknown') WHEN 'Critical' THEN 1 WHEN 'High' THEN 2
                WHEN 'Medium' THEN 3 WHEN 'Low' THEN 4 ELSE 5 END AS severity_rank,
           CASE WHEN d.kev THEN 'Yes' ELSE 'No' END AS kev_label,
           CASE WHEN d.epss IS NULL THEN 'N/A' WHEN d.epss < 0.1 THEN 'EPSS < 10%'
                WHEN d.epss < 0.5 THEN 'EPSS 10-50%' ELSE 'EPSS >= 50%' END AS epss_band,
           coalesce(d.fix_available, false) AS fix_available,
           d.vendor, d.product, coalesce(nullif(d.product_type, ''), 'unknown') AS product_type,
           coalesce(nullif(d.sources, '{}'), ARRAY['unknown']) AS sources,
           -- Version 5: the client's SLA. sla_status on the day of the run; deadline: the SLA due
           -- date when the decision has a priority, else the BOD 26-04 one.
           nullif(d.priority, '') AS priority, d.priority_rank, d.sla_rule, d.sla_since, d.sla_due,
           CASE WHEN d.sla_due IS NULL THEN NULL WHEN r.generated_at::date > d.sla_due THEN 'overdue'
                ELSE 'on-track' END AS sla_status,
           coalesce(d.sla_due, d.due_date) AS deadline
    FROM a2vm.decisions d JOIN a2vm.runs r USING (run_id);
ALTER VIEW a2vm.decision_facts SET (security_invoker = true);

-- A snapshot: for each tenant asked, its latest run on or before a day. The dashboards compare
-- two snapshots; a NULL day gives none. Runs with the caller's rights (row-level security).
CREATE OR REPLACE FUNCTION a2vm.snapshot_runs(tenants text[], snapshot_day date)
RETURNS TABLE (run_id bigint) LANGUAGE sql STABLE AS $$
    SELECT DISTINCT ON (r.tenant) r.run_id
    FROM a2vm.runs r
    WHERE r.tenant = ANY (tenants) AND r.generated_at::date <= snapshot_day
    ORDER BY r.tenant, r.generated_at DESC
$$;

-- Each run with the run of its tenant just before (version 3).
CREATE OR REPLACE VIEW a2vm.run_pairs AS
    SELECT r.run_id, r.tenant, r.generated_at,
           lag(r.run_id) OVER (PARTITION BY r.tenant ORDER BY r.generated_at) AS previous_run_id
    FROM a2vm.runs r;
ALTER VIEW a2vm.run_pairs SET (security_invoker = true);

-- Each finding of a run absent from the next run of its tenant (version 3). Outcome `fixed`: its
-- asset was scanned again in that run, after the finding's last observation, by a source that had
-- seen it; else `unverified`: gone, not checked (scan failed, host off, asset no longer listed).
-- Runs published before version 3 carry no scans: their findings come out unverified.
CREATE OR REPLACE VIEW a2vm.finding_closures AS
    SELECT p.tenant, p.run_id, p.generated_at AS closed_at, p.generated_at::date AS day,
           d.finding_id, d.asset, coalesce(d.asset_name, d.asset) AS asset_name, d.cve, d.level,
           CASE d.level WHEN 'ACT' THEN 1 WHEN 'ATTEND' THEN 2 ELSE 3 END AS level_rank,
           d.kev, d.bod_timeline, d.first_seen, d.due_date,
           (p.generated_at::date - d.first_seen) AS days_open,
           CASE WHEN d.due_date IS NULL THEN NULL ELSE p.generated_at::date <= d.due_date END AS within_due,
           CASE WHEN EXISTS (
               SELECT 1 FROM a2vm.assets a
               CROSS JOIN LATERAL jsonb_each_text(coalesce(d.seen_by, '{}'::jsonb)) s (source, seen)
               WHERE a.run_id = p.run_id AND a.asset = d.asset AND a.scans ? s.source
                 AND (a.scans ->> s.source)::timestamptz > s.seen::timestamptz
           ) THEN 'fixed' ELSE 'unverified' END AS outcome,
           -- Version 5: the client's SLA, met when fixed on or before its SLA due date.
           nullif(d.priority, '') AS priority, d.priority_rank, d.sla_due,
           CASE WHEN d.sla_due IS NULL THEN NULL ELSE p.generated_at::date <= d.sla_due END AS within_sla
    FROM a2vm.run_pairs p
    JOIN a2vm.decisions d ON d.run_id = p.previous_run_id
    WHERE NOT EXISTS (SELECT 1 FROM a2vm.decisions c WHERE c.run_id = p.run_id AND c.finding_id = d.finding_id);
ALTER VIEW a2vm.finding_closures SET (security_invoker = true);

-- The assets of each tenant's latest run with the date of their last scan (version 3).
CREATE OR REPLACE VIEW a2vm.latest_asset_scans AS
    SELECT a.tenant, r.tenant_name, r.generated_at, a.asset, coalesce(a.name, a.asset) AS asset_name, a.kind,
           a.act, a.attend, a.track, a.scans,
           (SELECT max(v::timestamptz) FROM jsonb_each_text(coalesce(a.scans, '{}'::jsonb)) s (k, v)) AS last_scan
    FROM a2vm.assets a JOIN a2vm.latest_runs r USING (run_id);
ALTER VIEW a2vm.latest_asset_scans SET (security_invoker = true);

-- The scan coverage with its run's date and the labels the dashboard groups on (version 4).
CREATE OR REPLACE VIEW a2vm.coverage_facts AS
    SELECT c.run_id, c.tenant, r.tenant_name, r.generated_at, r.generated_at::date AS day,
           c.asset, coalesce(c.name, c.asset) AS asset_name, c.state,
           CASE c.state WHEN 'not-in-cmdb' THEN 1 WHEN 'retired-but-alive' THEN 2 WHEN 'never-scanned' THEN 3
                WHEN 'stale' THEN 4 WHEN 'partial' THEN 5 WHEN 'not-scannable' THEN 6 WHEN 'not-expected' THEN 7
                ELSE 8 END AS state_rank,
           c.state IN ('not-scannable', 'never-scanned', 'stale', 'partial', 'covered') AS in_production,
           c.state IN ('not-in-cmdb', 'retired-but-alive', 'not-scannable', 'never-scanned', 'stale', 'partial')
               AS gap,
           coalesce(nullif(c.cmdb_class, ''), 'not in the CMDB') AS cmdb_class, c.cmdb_key, c.cmdb_status,
           coalesce(nullif(c.criticality, ''), 'unknown') AS criticality, c.cmdb_type, c.owner,
           c.expected, c.missing, c.scans, c.last_scan,
           (r.generated_at::date - c.last_scan::date) AS days_since_scan
    FROM a2vm.coverage c JOIN a2vm.runs r USING (run_id);
ALTER VIEW a2vm.coverage_facts SET (security_invoker = true);
CREATE OR REPLACE VIEW a2vm.latest_coverage AS
    SELECT f.* FROM a2vm.coverage_facts f JOIN a2vm.latest_runs r USING (run_id);
ALTER VIEW a2vm.latest_coverage SET (security_invoker = true);
DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['runs', 'decisions', 'assets', 'exposure_gaps', 'sources', 'coverage'] LOOP
        EXECUTE format('ALTER TABLE a2vm.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_read ON a2vm.%I', t);
        EXECUTE format(
            'CREATE POLICY tenant_read ON a2vm.%I FOR SELECT USING (EXISTS ('
            'SELECT 1 FROM a2vm.tenant_roles g WHERE g.role = current_user '
            'AND (g.tenant = %I.tenant OR g.tenant = ''*'')))', t, t);
    END LOOP;
END $$;

-- Reading roles granted before an upgrade read the new views too.
DO $$
DECLARE r name;
BEGIN
    FOR r IN SELECT DISTINCT g.role FROM a2vm.tenant_roles g JOIN pg_roles p ON p.rolname = g.role LOOP
        EXECUTE format('GRANT USAGE ON SCHEMA a2vm TO %I', r);
        EXECUTE format('GRANT SELECT ON ALL TABLES IN SCHEMA a2vm TO %I', r);
    END LOOP;
END $$;
