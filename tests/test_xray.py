"""Röntgen ve KVKK rapor uçları (sahte ClickHouse). Gerçek SQL e2e'de ClickHouse'a karşı koşar."""
import csv
import io

import pytest

from app import xray as xray_mod
from tests.test_gateway import client  # noqa: F401  (fixture)

ADMIN = "test-admin-token"
AUTH = {"Authorization": f"Bearer {ADMIN}"}


class FakeClickHouse:
    def __init__(self, rows_by_marker=None, fail=False):
        self.calls, self.rows_by_marker, self.fail = [], rows_by_marker or {}, fail

    async def query(self, sql, params):
        self.calls.append((sql, params))
        if self.fail:
            raise xray_mod.ClickHouseError("ClickHouse'a ulaşılamadı: ConnectError")
        for marker, rows in self.rows_by_marker.items():
            if marker in sql:
                return rows
        return [{}]


@pytest.fixture()
def admin(monkeypatch):
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", ADMIN)


def test_xray_requires_admin(client, monkeypatch):  # noqa: F811
    monkeypatch.delenv("TELVEGUARD_ADMIN_TOKEN", raising=False)
    assert client.get("/v1/xray").status_code == 404
    monkeypatch.setenv("TELVEGUARD_ADMIN_TOKEN", ADMIN)
    assert client.get("/v1/xray", headers={"Authorization": "Bearer yanlis"}).status_code == 401


def test_xray_without_clickhouse_is_503(client, admin):  # noqa: F811
    client.app.state.ch = None
    r = client.get("/v1/xray", headers=AUTH)
    assert r.status_code == 503 and r.json()["error"]["code"] == "clickhouse_disabled"


@pytest.mark.parametrize("days", [0, 367])
def test_xray_days_validated(client, admin, days):  # noqa: F811
    client.app.state.ch = FakeClickHouse()
    assert client.get(f"/v1/xray?days={days}", headers=AUTH).status_code == 400


def test_xray_assembles_sections_and_passes_params(client, admin):  # noqa: F811
    fake = FakeClickHouse({"uniqExact(user) AS users": [{"requests": 8, "external_unmasked_pii": 1}],
                           "GROUP BY team": [{"team": "analitik", "requests": 5}]})
    client.app.state.ch = fake
    r = client.get("/v1/xray?days=7&team=analitik", headers=AUTH)
    assert r.status_code == 200
    body = r.json()
    assert set(body) == {"window", *xray_mod.XRAY_QUERIES}
    assert body["summary"] == {"requests": 8, "external_unmasked_pii": 1}
    assert body["by_team"] == [{"team": "analitik", "requests": 5}]
    # Kullanıcı girdisi SQL'e gömülmez, parametre olarak gider
    assert all(params == {"days": 7, "team": "analitik"} for _, params in fake.calls)
    assert all("analitik" not in sql for sql, _ in fake.calls)


def test_xray_clickhouse_error_is_502(client, admin):  # noqa: F811
    client.app.state.ch = FakeClickHouse(fail=True)
    r = client.get("/v1/xray", headers=AUTH)
    assert r.status_code == 502 and r.json()["error"]["code"] == "clickhouse_error"


def test_xray_page_served_without_data(client):  # noqa: F811
    r = client.get("/xray")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
    assert "AI Kullanım Röntgeni" in r.text
    assert "https://" not in r.text  # air-gapped: harici kaynak yok


# ---------------- KVKK raporu ----------------

KVKK_ROWS = [
    {"team": "analitik", "model": "gpt-4o", "entity": "TCKN", "requests": 3, "users": 2,
     "blocked": 0, "masked_sent": 2, "unmasked_sent": 1},
    {"team": "=HYPERLINK(\"http://kotu\")", "model": "claude-opus-5", "entity": "IBAN_TR", "requests": 1,
     "users": 1, "blocked": 1, "masked_sent": 0, "unmasked_sent": 0},
]


@pytest.mark.parametrize("month", ["2026-13", "eylül", "2026", ""])
def test_kvkk_month_validated(client, admin, month):  # noqa: F811
    client.app.state.ch = FakeClickHouse()
    assert client.get(f"/v1/reports/kvkk-transfer?month={month}", headers=AUTH).status_code == 400


def test_kvkk_csv_is_excel_friendly_and_formula_safe(client, admin):  # noqa: F811
    fake = FakeClickHouse({"ARRAY JOIN entities AS entity\n    WHERE destination": KVKK_ROWS})
    client.app.state.ch = fake
    r = client.get("/v1/reports/kvkk-transfer?month=2026-12", headers=AUTH)
    assert r.status_code == 200
    assert 'filename="kvkk-yurtdisi-aktarim-2026-12.csv"' in r.headers["content-disposition"]
    text = r.content.decode("utf-8")
    assert text.startswith("\ufeff")  # Excel UTF-8 BOM
    rows = list(csv.reader(io.StringIO(text.lstrip("\ufeff")), delimiter=";"))
    assert rows[0][:4] == ["Ekip", "Sağlayıcı (yurt dışı)", "Model", "Kişisel veri türü"]
    assert rows[1][:4] == ["analitik", "OpenAI", "gpt-4o", "T.C. kimlik no"]
    assert rows[2][0] == "'=HYPERLINK(\"http://kotu\")"  # başında ' : formül olarak çalışmaz
    # Ay sınırları parametre olarak: Aralık -> ertesi yılın Ocak'ı
    assert fake.calls[0][1] == {"start": "2026-12-01", "end": "2027-01-01"}


def test_kvkk_json(client, admin):  # noqa: F811
    client.app.state.ch = FakeClickHouse({"ARRAY JOIN entities AS entity\n    WHERE destination": KVKK_ROWS[:1]})
    body = client.get("/v1/reports/kvkk-transfer?month=2026-09&format=json", headers=AUTH).json()
    assert body["rows"][0]["provider"] == "OpenAI" and body["rows"][0]["entity_label"] == "T.C. kimlik no"


async def test_clickhouse_client_sends_params_auth_and_alias_setting():
    import httpx
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["params"], seen["headers"], seen["body"] = dict(request.url.params), request.headers, request.content.decode()
        return httpx.Response(200, text='{"a": 1}\n{"a": 2}\n')

    ch = xray_mod.ClickHouse(httpx.AsyncClient(transport=httpx.MockTransport(handler)),
                             "http://ch:8123/", "okuyucu", "gizli", "telveguard")
    rows = await ch.query("SELECT {team:String} AS t", {"team": "x'; DROP TABLE audit --"})
    assert rows == [{"a": 1}, {"a": 2}]
    assert seen["params"]["param_team"] == "x'; DROP TABLE audit --"  # SQL'e değil parametreye
    assert seen["params"]["prefer_column_name_to_alias"] == "1" and seen["params"]["database"] == "telveguard"
    assert seen["params"]["output_format_json_quote_64bit_integers"] == "0"
    assert seen["headers"]["x-clickhouse-user"] == "okuyucu" and seen["headers"]["x-clickhouse-key"] == "gizli"
    assert seen["body"].endswith("FORMAT JSONEachRow") and "DROP" not in seen["body"]
