/**
 * The agent's state moves from OpenBao's KV into the database, each entry
 * signed by the key store (src/store.h). `data` is text, not jsonb: the
 * signature is over the bytes as written, and jsonb would write them anew.
 *
 * A v2 migration, for PostgreSQL and CockroachDB alike.
 */
#include <db_migrate.h>

static int migrate(schema_t *db) {

  return db->createTable("state", {
    key: {type: "text", primaryKey: true},
    version: {type: "bigint", notNull: true},
    data: {type: "text", notNull: true},
    mac: {type: "text", notNull: true},
    updated: {type: "timestamptz", notNull: true, defaultValue: {raw: "now()"}},
  });
}

DBM_MIGRATION_V2(migrate)
