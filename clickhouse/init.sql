-- Telveguard audit: Kafka -> ClickHouse (Kafka engine + Materialized View)
CREATE DATABASE IF NOT EXISTS telveguard;

CREATE TABLE IF NOT EXISTS telveguard.audit_queue
(
    event_id String, ts Int64, user String, team String, model String,
    destination String, action String, rules Array(String), reason String,
    entities Array(String), injection_score Float32, injection_engine String,
    prompt_sha256 String, prompt_chars UInt32, masked_prompt String,
    latency_ms Float32, upstream_status UInt16,
    output_entities Array(String), masked_count UInt16, output_scan String,
    -- gözlem modu, KVKK raporu ve Röntgen alanları
    monitored_rules Array(String), would_action String, masked_entities Array(String),
    prompt_tokens UInt32, completion_tokens UInt32, usage_known UInt8,
    est_cost_usd Nullable(Float64),
    -- kimlik (OIDC) ve çıktı koruması
    teams Array(String), auth_source String,
    output_leaked Array(String), output_action String, output_rules Array(String),
    api_format String
)
ENGINE = Kafka
SETTINGS kafka_broker_list = 'kafka:9092',
         kafka_topic_list = 'telveguard.audit.v1',
         kafka_group_name = 'clickhouse-telveguard-audit',
         kafka_format = 'JSONEachRow',
         input_format_skip_unknown_fields = 1;

CREATE TABLE IF NOT EXISTS telveguard.audit
(
    event_id UUID, event_time DateTime64(3, 'Europe/Istanbul'),
    user LowCardinality(String), team LowCardinality(String), model LowCardinality(String),
    destination LowCardinality(String), action LowCardinality(String),
    rules Array(LowCardinality(String)), reason String,
    entities Array(LowCardinality(String)), injection_score Float32,
    injection_engine LowCardinality(String), prompt_sha256 FixedString(64),
    prompt_chars UInt32, masked_prompt String CODEC(ZSTD(3)),
    latency_ms Float32, upstream_status UInt16,
    output_entities Array(LowCardinality(String)), masked_count UInt16,
    output_scan LowCardinality(String),
    monitored_rules Array(LowCardinality(String)), would_action LowCardinality(String),
    masked_entities Array(LowCardinality(String)),
    prompt_tokens UInt32, completion_tokens UInt32, usage_known UInt8,
    -- NULL = fiyatı bilinmiyor (0 = gerçekten ücretsiz / engellendi)
    est_cost_usd Nullable(Float64),
    teams Array(LowCardinality(String)), auth_source LowCardinality(String),
    -- model cevabında üretilen (girdide olmayan) PII / sır türleri ve uygulanan karar
    output_leaked Array(LowCardinality(String)), output_action LowCardinality(String),
    output_rules Array(LowCardinality(String)),
    -- istemci API biçimi: chat | responses | messages (Claude Code vb.)
    api_format LowCardinality(String)
)
ENGINE = MergeTree
PARTITION BY toYYYYMM(event_time)
ORDER BY (team, action, event_time)
-- KVKK "gerekli süre kadar saklama": saklama süresini politikanıza göre ayarlayın
TTL toDateTime(event_time) + INTERVAL 2 YEAR DELETE;

CREATE MATERIALIZED VIEW IF NOT EXISTS telveguard.audit_mv TO telveguard.audit AS
SELECT toUUID(event_id) AS event_id,
       fromUnixTimestamp64Milli(ts, 'Europe/Istanbul') AS event_time,
       user, team, model, destination, action, rules, reason, entities,
       injection_score, injection_engine, prompt_sha256, prompt_chars, masked_prompt,
       latency_ms, upstream_status, output_entities, masked_count, output_scan,
       monitored_rules, would_action, masked_entities,
       prompt_tokens, completion_tokens, usage_known, est_cost_usd,
       teams, auth_source, output_leaked, output_action, output_rules, api_format
FROM telveguard.audit_queue;

-- Örnek rapor: ekip bazında yurt dışına giden kişisel veri denemeleri (son 30 gün)
-- SELECT team, arrayJoin(entities) AS entity, countIf(action='mask') AS maskelenen,
--        countIf(action='block') AS engellenen
-- FROM telveguard.audit
-- WHERE destination='external' AND event_time > now() - INTERVAL 30 DAY
-- GROUP BY team, entity ORDER BY engellenen DESC, maskelenen DESC;
