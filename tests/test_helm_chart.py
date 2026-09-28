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


def render(*args):
    out = subprocess.run(["helm", "template", "tg", CHART, "--namespace", "ai", *args],
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
    out = subprocess.run(["helm", "lint", CHART, "--strict"], capture_output=True, text=True)
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
    assert c["command"][c["command"].index("--workers") + 1] == "4"
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
