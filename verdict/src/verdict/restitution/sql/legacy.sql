-- SPDX-License-Identifier: LicenseRef-ngvm-proprietary
-- A reporting database of A2VM (before v0.25.0, schema a2vm) renamed, and kept: run before
-- schema.sql and before a grant. Does nothing on a database of NGVM.
DO $$
DECLARE c record;
BEGIN
    IF to_regnamespace('a2vm') IS NOT NULL AND to_regnamespace('ngvm') IS NULL THEN
        ALTER SCHEMA a2vm RENAME TO ngvm;
    END IF;
    FOR c IN SELECT k.relname, k.relkind FROM pg_attribute a JOIN pg_class k ON k.oid = a.attrelid
             JOIN pg_namespace n ON n.oid = k.relnamespace
             WHERE n.nspname = 'ngvm' AND a.attname = 'a2vm_version' AND NOT a.attisdropped
             ORDER BY k.relkind DESC  -- tables (r) before views (v)
    LOOP
        EXECUTE format('ALTER %s ngvm.%I RENAME COLUMN a2vm_version TO ngvm_version',
                       CASE c.relkind WHEN 'v' THEN 'VIEW' ELSE 'TABLE' END, c.relname);
    END LOOP;
END $$;
