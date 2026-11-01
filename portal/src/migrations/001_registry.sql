-- v1: encrypted registry, separate from Synapse events and media.
CREATE TABLE IF NOT EXISTS portal_registry (
  id integer PRIMARY KEY CHECK (id = 1),
  schema_version integer NOT NULL DEFAULT 1 CHECK (schema_version = 1),
  payload bytea NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
