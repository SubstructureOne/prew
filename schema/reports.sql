CREATE TYPE pgpkttype AS ENUM (
    'Startup',
    'Query',
    'Other'
);

CREATE TABLE IF NOT EXISTS reports (
    packet_id bigserial PRIMARY KEY,
    packet_type pgpkttype NOT NULL,
    packet_time timestamp NOT NULL DEFAULT now(),
    packet_info jsonb,
    packet_bytes bytea
);