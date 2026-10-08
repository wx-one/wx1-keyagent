/**
 * The database as wx1-keyagent first had it: requests and their history,
 * leases, the log of key fetches, and the sessions of the key release.
 * Nothing a key release depends on lives here - that is in OpenBao.
 *
 * A v2 migration: it says only what it builds, and meta-db-migrate learns
 * how to undo it. Written for PostgreSQL and CockroachDB alike.
 */
#include <db_migrate.h>

static int migrate(schema_t *db) {

  db->createTable("requests", {
    id: {type: "bigint", primaryKey: true, autoIncrement: true},
    created: {type: "timestamptz", notNull: true, defaultValue: {raw: "now()"}},
    type: {type: "text", notNull: true},
    payload: {type: "jsonb", notNull: true},
    status: {type: "text", notNull: true},
    reason: {type: "text", notNull: true, defaultValue: ""},
    checks: {type: "jsonb", notNull: true, defaultValue: {raw: "'[]'"}},
    decided: {type: "timestamptz"},
    decided_by: {type: "text", notNull: true, defaultValue: ""},
  });
  db->addIndex("requests", "requests_open", ["status", "id"]);

  db->createTable("leases", {
    disk_id: {type: "text", primaryKey: true},
    report_id: {type: "text", notNull: true},
    chip_id: {type: "text", notNull: true},
    expires: {type: "timestamptz", notNull: true},
    first_seen: {type: "timestamptz", notNull: true},
  });

  db->createTable("releases", {
    id: {type: "bigint", primaryKey: true, autoIncrement: true},
    ts: {type: "timestamptz", notNull: true, defaultValue: {raw: "now()"}},
    disk_id: {type: "text", notNull: true, defaultValue: ""},
    step: {type: "text", notNull: true},
    ok: {type: "boolean", notNull: true},
    detail: {type: "text", notNull: true, defaultValue: ""},
    ctx: {type: "jsonb", notNull: true, defaultValue: {raw: "'{}'"}},
    source: {type: "text", notNull: true, defaultValue: ""},
  });
  db->addIndex("releases", "releases_disk", ["disk_id", "id"]);

  /* a key release in three calls, possibly on three workers; of the
     activation secret only its hash */
  db->createTable("sessions", {
    id: {type: "text", primaryKey: true},
    disk_id: {type: "text", notNull: true},
    nonce: {type: "text", notNull: true},
    expires: {type: "timestamptz", notNull: true},
    renew: {type: "boolean", notNull: true},
    ending: {type: "boolean", notNull: true},
    stage: {type: "text", notNull: true},
    secret_hash: {type: "text", notNull: true, defaultValue: ""},
    quote_nonce: {type: "text", notNull: true, defaultValue: ""},
    ak_pub: {type: "text", notNull: true, defaultValue: ""},
    guest_pub: {type: "text", notNull: true, defaultValue: ""},
    ek: {type: "text", notNull: true, defaultValue: ""},
    persist: {type: "boolean", notNull: true, defaultValue: false},
    report_id: {type: "text", notNull: true, defaultValue: ""},
    chip_id: {type: "text", notNull: true, defaultValue: ""},
    host_data: {type: "text", notNull: true, defaultValue: ""},
  });

  return db->addIndex("sessions", "sessions_expires", ["expires"]);
}

DBM_MIGRATION_V2(migrate)
