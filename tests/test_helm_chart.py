"""
Helm chart testleri: `helm template` çıktısı ayrıştırılıp kontrol edilir.
Kümeye BAĞLANMAZ (lint/template tamamen yerel). helm yoksa atlanır.
"""
import shutil
import subprocess

import pytest
import yaml

CHART = "deploy/helm/telveguard-gateway"
pytestmark = pytest.mark.skipif(not shutil.which("helm"), reason="helm kurulu değil")


# Chart varsayılanı auth.mode=jwt: issuer + audience olmadan kurulum reddedilir
OIDC = ["--set", "auth.oidc.issuer=https://sso.sirket.local/realms/ai", "--set", "auth.oidc.audience=telveguard"]


def render(*args, oidc=True):
    out = subprocess.run(["helm", "template", "tg", CHART, "--namespace", "ai", *(OIDC if oidc else []), *args],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(out.stderr)
    docs = [d for d in yaml.safe_load_all(out.stdout) if d]
    return {(d["kind"], d["metadata"]["name"]): d for d in docs}


def container(docs):
    return docs[("Deployment", "tg-telveguard-gateway")]["spec"]["template"]["spec"]["containers"][0]


def env(docs):
    return {e["name"]: e for e in container(docs)["env"]}


def test_lint_passes():
    out = subprocess.run(["helm", "lint", CHART, "--strict", *OIDC], capture_output=True, text=True)
    assert out.returncode == 0, out.stdout + out.stderr


def test_default_render_is_okd_ready():
    docs = render()
    kinds = {k for k, _ in docs}
    assert {"Deployment", "Service", "ConfigMap", "Secret", "ServiceAccount", "Route",
            "PodDisruptionBudget"} <= kinds
    assert "Ingress" not in kinds and "HorizontalPodAutoscaler" not in kinds
    pod = docs[("Deployment", "tg-telveguard-gateway")]["spec"]["template"]["spec"]
    # OKD restricted-v2: rastgele UID -> runAsUser yok, root değil, yetki yükseltme yok
    assert "runAsUser" not in pod["securityContext"] and pod["securityContext"]["runAsNonRoot"] is True
    c = container(docs)
    assert c["securityContext"]["readOnlyRootFilesystem"] is True
    assert c["securityContext"]["capabilities"]["drop"] == ["ALL"]
    assert pod["automountServiceAccountToken"] is False
    assert {m["mountPath"] for m in c["volumeMounts"]} == {"/policies", "/tmp"}
    assert c["readinessProbe"]["httpGet"]["path"] == "/healthz"
    # Uzun LLM cevapları için router zaman aşımı
    route = docs[("Route", "tg-telveguard-gateway")]
    assert route["metadata"]["annotations"]["haproxy.router.openshift.io/timeout"] == "180s"
    assert route["spec"]["tls"]["termination"] == "edge"


def test_policy_configmap_matches_repo_policy():
    """Chart'taki kopya policies/default.yaml ile birebir aynı olmalı (sessiz ayrışma olmasın)."""
    chart_copy = open(f"{CHART}/files/policy.yaml", encoding="utf-8").read()
    assert chart_copy == open("policies/default.yaml", encoding="utf-8").read(), \
        "Güncelleyin: cp policies/default.yaml deploy/helm/telveguard-gateway/files/policy.yaml"
    cm = render()[("ConfigMap", "tg-telveguard-gateway-policy")]
    assert yaml.safe_load(cm["data"]["policy.yaml"]) == yaml.safe_load(chart_copy)


def test_secrets_are_optional_refs_and_not_rendered_when_empty():
    docs = render()
    e = env(docs)
    ref = e["TELVEGUARD_ADMIN_TOKEN"]["valueFrom"]["secretKeyRef"]
    assert ref == {"name": "tg-telveguard-gateway", "key": "admin-token", "optional": True}
    assert not docs[("Secret", "tg-telveguard-gateway")].get("stringData")  # boş değer yazılmaz
    assert "KAFKA_BOOTSTRAP" not in e and "CLICKHOUSE_URL" not in e


def test_existing_secret_and_configmap_are_used():
    docs = render("--set", "existingSecret=tg-sirlar", "--set", "policy.existingConfigMap=kurum-politikasi")
    assert ("Secret", "tg-telveguard-gateway") not in docs
    assert not any(k == "ConfigMap" for k, _ in docs)
    assert env(docs)["UPSTREAM_EXTERNAL_KEY"]["valueFrom"]["secretKeyRef"]["name"] == "tg-sirlar"
    vols = docs[("Deployment", "tg-telveguard-gateway")]["spec"]["template"]["spec"]["volumes"]
    assert {"name": "policy", "configMap": {"name": "kurum-politikasi"}} in vols


def test_policy_change_rolls_pods():
    a = render()[("Deployment", "tg-telveguard-gateway")]["spec"]["template"]["metadata"]["annotations"]
    b = render("--set-string", "policy.content=default_action: allow")[("Deployment", "tg-telveguard-gateway")]
    assert a["checksum/policy"] != b["spec"]["template"]["metadata"]["annotations"]["checksum/policy"]


def test_full_config_renders_env():
    docs = render("--set", "audit.kafkaBootstrap=kafka:9092", "--set", "clickhouse.url=http://ch:8123",
                  "--set", "audit.storeMasked=true", "--set", "workers=4",
                  "--set", "models.existingClaim=tg-models", "--set", "models.enableTrNer=true")
    e = env(docs)
    assert e["KAFKA_BOOTSTRAP"]["value"] == "kafka:9092" and e["CLICKHOUSE_URL"]["value"] == "http://ch:8123"
    assert e["AUDIT_STORE_MASKED"]["value"] == "1" and e["ENABLE_TR_NER"]["value"] == "1"
    c = container(docs)
    assert e["WORKERS"]["value"] == "4"
    assert "startupProbe" in c and any(m["mountPath"] == "/models" for m in c["volumeMounts"])


def test_kubernetes_mode_with_ingress_hpa_networkpolicy():
    docs = render("--set", "route.enabled=false", "--set", "ingress.enabled=true",
                  "--set", "autoscaling.enabled=true", "--set", "networkPolicy.enabled=true")
    kinds = {k for k, _ in docs}
    assert {"Ingress", "HorizontalPodAutoscaler", "NetworkPolicy"} <= kinds and "Route" not in kinds
    assert "replicas" not in docs[("Deployment", "tg-telveguard-gateway")]["spec"]  # HPA yönetir


@pytest.mark.parametrize("args,msg", [
    (["--set", "models.enableTrNer=true"], "existingClaim"),
    (["--set", "ingress.enabled=true"], "aynı anda"),
    (["--set", "policy.existingConfigMap=x", "--set-string", "policy.content=a: 1"], "birlikte"),
    (["--set", "workers=0"], "workers"),
])
def test_invalid_config_fails_fast(args, msg):
    with pytest.raises(RuntimeError, match=msg):
        render(*args)


def test_jwt_is_default_and_requires_issuer():
    with pytest.raises(RuntimeError, match="auth.oidc.issuer"):
        render(oidc=False)
    e = env(render("--set", "auth.oidc.teamPrefix=telveguard-"))
    assert e["AUTH_MODE"]["value"] == "jwt"
    assert e["OIDC_ISSUER"]["value"] == "https://sso.sirket.local/realms/ai"
    assert e["OIDC_AUDIENCE"]["value"] == "telveguard" and e["OIDC_TEAM_PREFIX"]["value"] == "telveguard-"


def test_header_mode_must_be_explicit_and_has_no_oidc_env():
    e = env(render("--set", "auth.mode=header", oidc=False))
    assert e["AUTH_MODE"]["value"] == "header" and "OIDC_ISSUER" not in e
    with pytest.raises(RuntimeError, match="geçersiz"):
        render("--set", "auth.mode=ldap")


def test_image_entrypoint_used_with_workers_and_multiproc_metrics():
    c = container(render("--set", "workers=3"))
    assert "command" not in c                      # imajın entrypoint.sh'ı kullanılır
    e = {x["name"]: x.get("value") for x in c["env"]}
    assert e["WORKERS"] == "3" and e["PROMETHEUS_MULTIPROC_DIR"].startswith("/tmp/")  # /tmp emptyDir


def test_service_monitor_optional():
    assert not any(k == "ServiceMonitor" for k, _ in render())
    sm = render("--set", "metrics.serviceMonitor.enabled=true")[("ServiceMonitor", "tg-telveguard-gateway")]
    assert sm["spec"]["endpoints"][0]["path"] == "/metrics"


def test_anthropic_upstream_env_and_secret_refs():
    e = env(render("--set", "upstream.anthropicInternalUrl=http://vllm-anthropic:8000"))
    assert e["UPSTREAM_ANTHROPIC_URL"]["value"] == "https://api.anthropic.com"
    assert e["UPSTREAM_ANTHROPIC_INTERNAL_URL"]["value"] == "http://vllm-anthropic:8000"
    assert e["UPSTREAM_ANTHROPIC_KEY"]["valueFrom"]["secretKeyRef"]["key"] == "upstream-anthropic-key"
    assert "UPSTREAM_ANTHROPIC_INTERNAL_URL" not in env(render())   # tanımsızsa yok


def test_admin_group_env():
    assert "OIDC_ADMIN_GROUP" not in env(render())
    assert env(render("--set", "auth.oidc.adminGroup=telveguard-admin"))["OIDC_ADMIN_GROUP"]["value"] == "telveguard-admin"


def test_quota_redis_env_and_password_secret():
    assert "REDIS_URL" not in env(render())
    e = env(render("--set", "quota.redisUrl=redis://redis:6379/0"))
    assert e["REDIS_URL"]["value"] == "redis://redis:6379/0"
    assert e["REDIS_PASSWORD"]["valueFrom"]["secretKeyRef"]["key"] == "redis-password"


REDIS = ["--set", "quota.redisUrl=redis://redis:6379/0"]


def test_policy_store_env():
    assert "POLICY_STORE" not in env(render())
    e = env(render("--set", "policy.store.enabled=true", "--set", "clickhouse.url=http://ch:8123", *REDIS))
    assert e["POLICY_STORE"]["value"] == "clickhouse" and e["POLICY_FOUR_EYES"]["value"] == "1"
    assert e["POLICY_EMERGENCY"]["value"] == "1"
    assert e["POLICY_STORE_CLICKHOUSE_USER"]["value"] == "telveguard_policy"
    assert e["POLICY_STORE_CLICKHOUSE_PASSWORD"]["valueFrom"]["secretKeyRef"]["key"] == "policy-store-password"
    with pytest.raises(RuntimeError, match="clickhouse.url"):
        render("--set", "policy.store.enabled=true")


def test_icap_optional_with_own_service_and_networkpolicy():
    docs = render()
    assert "ICAP_PORT" not in env(docs) and ("Service", "tg-telveguard-gateway-icap") not in docs
    docs = render("--set", "icap.enabled=true", "--set", "icap.allowedClients={10.20.30.0/24,10.20.31.5/32}",
                  "--set", "networkPolicy.enabled=true")
    e = env(docs)
    assert e["ICAP_PORT"]["value"] == "1344" and e["ICAP_ALLOWED_CLIENTS"]["value"] == "10.20.30.0/24,10.20.31.5/32"
    assert {"name": "icap", "containerPort": 1344, "protocol": "TCP"} in container(docs)["ports"]
    svc = docs[("Service", "tg-telveguard-gateway-icap")]["spec"]
    assert svc["type"] == "LoadBalancer" and svc["externalTrafficPolicy"] == "Local"
    rules = docs[("NetworkPolicy", "tg-telveguard-gateway")]["spec"]["ingress"]
    assert rules[1]["from"] == [{"ipBlock": {"cidr": "10.20.30.0/24"}}, {"ipBlock": {"cidr": "10.20.31.5/32"}}]
    with pytest.raises(RuntimeError, match="allowedClients"):
        render("--set", "icap.enabled=true")


def test_inventory_in_configmap_matches_repo():
    chart_copy = open(f"{CHART}/files/inventory.yaml", encoding="utf-8").read()
    assert chart_copy == open("policies/inventory.yaml", encoding="utf-8").read(), \
        "Güncelleyin: cp policies/inventory.yaml deploy/helm/telveguard-gateway/files/inventory.yaml"
    docs = render()
    cm = docs[("ConfigMap", "tg-telveguard-gateway-policy")]
    assert yaml.safe_load(cm["data"]["inventory.yaml"]) == yaml.safe_load(chart_copy)
    assert env(docs)["INVENTORY_PATH"]["value"] == "/policies/inventory.yaml"


def test_policy_git_env():
    base = ["--set", "policy.store.enabled=true", "--set", "clickhouse.url=http://ch:8123", *REDIS]
    assert "POLICY_GIT_PROVIDER" not in env(render(*base))
    e = env(render(*base, "--set", "policy.store.git.enabled=true", "--set", "policy.store.git.url=https://bb.sirket.local",
                   "--set", "policy.store.git.project=SEC", "--set", "policy.store.git.repo=tg-config",
                   "--set", "policy.store.git.mode=pull_request", "--set", "policy.store.git.reviewers={uyum,guvenlik}"))
    assert e["POLICY_GIT_PROVIDER"]["value"] == "bitbucket-dc" and e["POLICY_GIT_MODE"]["value"] == "pull_request"
    assert e["POLICY_GIT_PR_REVIEWERS"]["value"] == "uyum,guvenlik" and e["POLICY_GIT_STRICT"]["value"] == "0"
    assert e["POLICY_GIT_TOKEN"]["valueFrom"]["secretKeyRef"]["key"] == "policy-git-token"
    with pytest.raises(RuntimeError, match="url, project ve repo"):
        render(*base, "--set", "policy.store.git.enabled=true")
    with pytest.raises(RuntimeError, match="policy.store.enabled gerekli"):
        render("--set", "policy.store.git.enabled=true")


def test_policy_store_needs_redis_with_multiple_processes():
    store = ["--set", "policy.store.enabled=true", "--set", "clickhouse.url=http://ch:8123"]
    with pytest.raises(RuntimeError, match="quota.redisUrl"):
        render(*store)                                             # varsayılan: 2 replica x 2 worker
    assert env(render(*store, "--set", "replicaCount=1", "--set", "workers=1"))["POLICY_STORE"]["value"] == "clickhouse"
    e = env(render(*store, *REDIS, "--set", "policy.store.emergency=false"))
    assert e["POLICY_EMERGENCY"]["value"] == "0"


def test_request_limit_and_kafka_security_env():
    e = env(render())
    assert e["MAX_REQUEST_BYTES"]["value"] == "32000000" and e["KAFKA_SECURITY_PROTOCOL"]["value"] == "PLAINTEXT"
    assert "KAFKA_SASL_PASSWORD" not in e
    e = env(render("--set", "audit.kafka.securityProtocol=SASL_SSL", "--set", "audit.kafka.saslUsername=tg",
                   "--set", "audit.kafka.caFile=/etc/pki/ca.pem"))
    assert (e["KAFKA_SASL_MECHANISM"]["value"], e["KAFKA_SASL_USERNAME"]["value"]) == ("SCRAM-SHA-512", "tg")
    assert e["KAFKA_SASL_PASSWORD"]["valueFrom"]["secretKeyRef"]["key"] == "kafka-sasl-password"
    assert e["KAFKA_SSL_CA_FILE"]["value"] == "/etc/pki/ca.pem"
    with pytest.raises(RuntimeError, match="saslUsername"):
        render("--set", "audit.kafka.securityProtocol=SASL_SSL")
    with pytest.raises(RuntimeError, match="securityProtocol"):
        render("--set", "audit.kafka.securityProtocol=TLS")


def test_metrics_token_wires_env_and_service_monitor():
    with pytest.raises(RuntimeError, match="metricsToken"):
        render("--set", "metrics.requireToken=true")
    docs = render("--set", "metrics.requireToken=true", "--set", "secrets.metricsToken=prom",
                  "--set", "metrics.serviceMonitor.enabled=true")
    assert env(docs)["METRICS_TOKEN"]["valueFrom"]["secretKeyRef"]["key"] == "metrics-token"
    auth = docs[("ServiceMonitor", "tg-telveguard-gateway")]["spec"]["endpoints"][0]["authorization"]
    assert auth == {"type": "Bearer", "credentials": {"name": "tg-telveguard-gateway", "key": "metrics-token"}}
    assert docs[("Secret", "tg-telveguard-gateway")]["stringData"]["metrics-token"] == "prom"


def test_okd_example_values_render():
    """docs/okd-kurulum.md'deki örnek değerler kurulabilir olmalı; kurum CA'sı pod'a bağlanır."""
    docs = render("-f", "deploy/helm/values-okd.example.yaml", oidc=False)
    c, e = container(docs), env(docs)
    assert {"Route", "NetworkPolicy", "ServiceMonitor"} <= {k for k, _ in docs}
    assert ("Secret", "tg-telveguard-gateway") not in docs           # sırlar existingSecret'ta
    assert e["KAFKA_SSL_CA_FILE"]["value"] == "/etc/kurum-ca/ca.pem"
    assert {"name": "kurum-ca", "mountPath": "/etc/kurum-ca", "readOnly": True} in c["volumeMounts"]
    pod = docs[("Deployment", "tg-telveguard-gateway")]["spec"]["template"]["spec"]
    assert {"name": "kurum-ca", "configMap": {"name": "kurum-ca"}} in pod["volumes"]
