-- 0.3.0: ilgili kişi başvurusu (KVKK md. 11) için subject_hashes sütunu.
-- Mevcut kurulumda BİR KEZ, yazma yetkili kullanıcıyla çalıştırın:
--   clickhouse-client --multiquery < clickhouse/migrations/0.3.0-subject-hashes.sql
-- Yeni kurulumda gerekmez (init.sql zaten içerir).
--
-- Kafka tablosu ALTER desteklemez: kuyruk ve materialized view yeniden oluşturulur. Tüketici
-- grubu (kafka_group_name) aynı kaldığı için arada Kafka'ya yazılan olaylar kaybolmaz; yeniden
-- oluşturma sonrası kaldığı yerden okunur. Gateway'i bu adımdan önce ya da sonra güncellemek
-- fark etmez (bilinmeyen alan yok sayılır, eksik alan boş dizi olur).
-- DİKKAT: aşağıdaki kafka_broker_list / topic / group değerlerini kendi kurulumunuzdaki
-- audit_queue ile aynı yapın (SHOW CREATE TABLE telveguard.audit_queue).

ALTER TABLE telveguard.audit ADD COLUMN IF NOT EXISTS subject_hashes Array(String) CODEC(ZSTD(3));
ALTER TABLE telveguard.audit ADD INDEX IF NOT EXISTS subject_idx subject_hashes TYPE bloom_filter(0.01) GRANULARITY 4;

DROP VIEW IF EXISTS telveguard.audit_mv;
DROP TABLE IF EXISTS telveguard.audit_queue;

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
    api_format String, quota String,
    -- ilgili kişi başvurusu: tanımlayıcıların anahtarlı özeti (ham değer değil)
    subject_hashes Array(String)
)
ENGINE = Kafka
SETTINGS kafka_broker_list = 'kafka:9092',
         kafka_topic_list = 'telveguard.audit.v1',
         kafka_group_name = 'clickhouse-telveguard-audit',
         kafka_format = 'JSONEachRow',
         input_format_skip_unknown_fields = 1;

CREATE MATERIALIZED VIEW IF NOT EXISTS telveguard.audit_mv TO telveguard.audit AS
SELECT toUUID(event_id) AS event_id,
       fromUnixTimestamp64Milli(ts, 'Europe/Istanbul') AS event_time,
       user, team, model, destination, action, rules, reason, entities,
       injection_score, injection_engine, prompt_sha256, prompt_chars, masked_prompt,
       latency_ms, upstream_status, output_entities, masked_count, output_scan,
       monitored_rules, would_action, masked_entities,
       prompt_tokens, completion_tokens, usage_known, est_cost_usd,
       teams, auth_source, output_leaked, output_action, output_rules, api_format, quota,
       subject_hashes
FROM telveguard.audit_queue;
