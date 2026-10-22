-- SPDX-License-Identifier: LicenseRef-a2vm-proprietary
-- Reporting database of A2VM (schema a2vm, version 1): the reporting datasets of every run and
-- tenant, read by dashboarding and reporting tools. Idempotent: run again on every init.
-- Objects are owned by the writer role (the A2VM jobs); readers get SELECT, limited to their
-- tenants by row-level security (a2vm.tenant_roles).

CREATE SCHEMA IF NOT EXISTS a2vm;

CREATE TABLE IF NOT EXISTS a2vm.schema_version (version integer PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now());
INSERT INTO a2vm.schema_version (version) VALUES (1) ON CONFLICT DO NOTHING;

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

CREATE TABLE IF NOT EXISTS a2vm.exposure_gaps (
    run_id   bigint NOT NULL REFERENCES a2vm.runs ON DELETE CASCADE,
    tenant   text NOT NULL,
    kind     text NOT NULL,
    asset    text NOT NULL,
    name     text,
    declared text,
    detail   text
);

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

DO $$
DECLARE t text;
BEGIN
    FOREACH t IN ARRAY ARRAY['runs', 'decisions', 'assets', 'exposure_gaps', 'sources'] LOOP
        EXECUTE format('ALTER TABLE a2vm.%I ENABLE ROW LEVEL SECURITY', t);
        EXECUTE format('DROP POLICY IF EXISTS tenant_read ON a2vm.%I', t);
        EXECUTE format(
            'CREATE POLICY tenant_read ON a2vm.%I FOR SELECT USING (EXISTS ('
            'SELECT 1 FROM a2vm.tenant_roles g WHERE g.role = current_user '
            'AND (g.tenant = %I.tenant OR g.tenant = ''*'')))', t, t);
    END LOOP;
END $$;
