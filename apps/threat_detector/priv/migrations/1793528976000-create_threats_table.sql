CREATE TYPE threat_level AS ENUM ('informational', 'low', 'medium', 'high', 'critical');

CREATE TABLE threats (
    rule               TEXT         NOT NULL,
    rule_instance_hash BYTEA        NOT NULL,
    subject_id         TEXT         NOT NULL,
    level              threat_level NOT NULL,
    details            JSONB       NOT NULL,
    tags               JSONB       NOT NULL DEFAULT '[]',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at         TIMESTAMPTZ,
    CONSTRAINT threats_pkey PRIMARY KEY (rule, rule_instance_hash)
);

CREATE INDEX threats_subject_id_idx ON threats (subject_id);
