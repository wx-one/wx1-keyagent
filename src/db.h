/**
 * The database: what may be lost without a key release depending on it -
 * requests and their history, leases, and the log of key fetches.
 * PostgreSQL or CockroachDB; everything here is written to work on both.
 *
 * The schema comes from migrations/ (meta-db-migrate, v2), compiled into the
 * program and run at start-up - the agent stays one binary, and needs
 * nothing of meta or meta-db-migrate at run time.
 */
#ifndef WX_DB_H
#define WX_DB_H

#include "util.h"

#include <db_migrate.h>
#include <meta_pg.h>
#include <meta_sql.h>

static const char *dbUrl(void) {
  return env("WX_DB", "postgresql://root@127.0.0.1:26257/keyagent?sslmode=disable");
}

/** "pg" or "cockroachdb": which of meta-db-migrate's drivers speaks to it. */
static const char *dbDriver(void) {
  return env("WX_DB_DRIVER", "pg");
}

/* an error arrives as one entry of several lines (migration, step, the SQL
   with a marker, the driver's fields): each gets the prefix, so a log
   collector keeps them with the agent */
static void dbMigrateSays(int level, const char *line) {
  (void)level;
  for (;;) {
    const char *end = strchr(line, '\n');
    int len = end ? (int)(end - line) : (int)strlen(line);
    fprintf(stderr, "wx1-keyagent: migrate: %.*s\n", len, line);
    if (!end || !end[1]) break;
    line = end + 1;
  }
}

/**
 * Brings the schema to the newest migration (migrations/, compiled into the
 * program; meta-db-migrate v2). Run once, in nginx's master before any
 * worker serves, so blocking is fine; the migration lock in the database
 * keeps two agents starting at once from migrating at once.
 */
static int dbMigrate(void) {

  char why[512] = "";
  yyjson_mut_doc *doc = yyjson_mut_doc_new(NULL);
  yyjson_mut_val *config = yyjson_mut_obj(doc);

  yyjson_mut_doc_set_root(doc, config);
  yyjson_mut_obj_add_str(doc, config, "driver", dbDriver());
  yyjson_mut_obj_add_str(doc, config, "url", dbUrl());

  dbmSetLogger(dbMigrateSays);

  json_t settings = meta_jsonFromMut(doc);
  int failed = dbmMigrateUp(settings, NULL, why, sizeof why);
  settings.release();

  dbmSetLogger(NULL);

  if (failed != 0) {
    fprintf(stderr, "wx1-keyagent: the database cannot be migrated: %s\n", why);
    return 1;
  }

  return 0;
}

/**
 * One connection per worker, and one query on it at a time.
 *
 * Tasks of one worker interleave wherever one of them waits, and a libpq
 * connection takes one statement at a time - a second task sending while the
 * first waits for its answer gets "another command is already in progress",
 * or worse, the first one's rows. The channel holds a single token: whoever
 * has it may use the connection.
 */
typedef @chan(int, 1) dbTurn_t;

static PGconn *database;
static dbTurn_t dbTurn;

static int dbConnect(void) {

  database = meta_pgOpen(dbUrl());

  if (database == NULL) {
    fprintf(stderr, "wx1-keyagent: this worker cannot reach the database\n");
    return 1;
  }

  dbTurn.send(1);

  return 0;
}

/** A statement with its values beside it. The caller clears the result. */
META_OWNS static PGresult *dbAsk(const sql_t *query) {

  int token;
  PGresult *r;

  if (database == NULL || !dbTurn.receive(&token))
    return NULL;

  r = database.ask(query);

  /* a broken connection is opened again for the next one */
  if (r == NULL && PQstatus(database) != CONNECTION_OK)
    PQreset(database);

  dbTurn.send(token);

  return r;
}

/** True when a statement that returns no rows went through. */
static bool dbDo(const sql_t *query) {

  PGresult *r = dbAsk(query);
  bool done = r != NULL && PQresultStatus(r) == PGRES_COMMAND_OK;

  if (r != NULL)
    PQclear(r);

  return done;
}

#endif /* WX_DB_H */
