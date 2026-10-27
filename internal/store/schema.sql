-- anydec project database. One SQLite file per project, next to the input.
-- The input's bytes are stored too, so the file alone reopens the project.

CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id        INTEGER PRIMARY KEY,
    parent_id INTEGER REFERENCES artifacts(id),
    offset    INTEGER NOT NULL DEFAULT 0,
    kind      TEXT    NOT NULL,
    path      TEXT,
    sha256    TEXT    NOT NULL,
    data      BLOB
);

CREATE TABLE IF NOT EXISTS segments (
    id          INTEGER PRIMARY KEY,
    artifact_id INTEGER NOT NULL REFERENCES artifacts(id),
    name        TEXT,
    address     INTEGER NOT NULL,
    size        INTEGER NOT NULL,
    perms       TEXT    NOT NULL -- subset of "rwx"
);

CREATE TABLE IF NOT EXISTS symbols (
    id          INTEGER PRIMARY KEY,
    artifact_id INTEGER NOT NULL REFERENCES artifacts(id),
    address     INTEGER NOT NULL,
    name        TEXT    NOT NULL,
    kind        TEXT    NOT NULL, -- function, object, import, ...
    source      TEXT    NOT NULL  -- elf, dwarf, signature, user, ...
);

CREATE TABLE IF NOT EXISTS functions (
    address   INTEGER PRIMARY KEY,
    name      TEXT NOT NULL,
    prototype TEXT,
    status    TEXT NOT NULL DEFAULT 'discovered',
    overrides TEXT -- JSON of user overrides
);

CREATE TABLE IF NOT EXISTS ir_cache (
    function_address INTEGER NOT NULL REFERENCES functions(address),
    pass             TEXT    NOT NULL,
    pass_version     INTEGER NOT NULL,
    ir               BLOB    NOT NULL,
    PRIMARY KEY (function_address, pass, pass_version)
);

CREATE TABLE IF NOT EXISTS types (
    id         INTEGER PRIMARY KEY,
    name       TEXT NOT NULL,
    definition TEXT NOT NULL, -- JSON
    source     TEXT NOT NULL  -- recovered or user
);

CREATE TABLE IF NOT EXISTS annotations (
    id         INTEGER PRIMARY KEY,
    address    INTEGER NOT NULL,
    kind       TEXT    NOT NULL, -- rename, comment, bookmark
    value      TEXT    NOT NULL,
    author     TEXT,
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
);
