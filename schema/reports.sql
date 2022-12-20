CREATE TYPE pgpkttype AS ENUM (
    'Startup',
    'Query',
    'Other'
);

CREATE TYPE pktdirection AS ENUM (
    'Forward',
    'Backward'
);

CREATE TABLE IF NOT EXISTS reports (
    packet_id bigserial PRIMARY KEY,
    username text,
    packet_type pgpkttype NOT NULL,
    packet_time timestamp NOT NULL DEFAULT now(),
    direction pktdirection,
    packet_info jsonb,
    packet_bytes bytea,
    charged boolean NOT NULL DEFAULT FALSE
);

CREATE INDEX reports_not_charged_index ON reports (packet_id) WHERE NOT charged;
