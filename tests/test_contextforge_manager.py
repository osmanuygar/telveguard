"""ContextForge'un kullandığı gerçek PluginManager ile uçtan uca yükleme testi."""
import pytest

pytest.importorskip("cpex.framework")

from cpex.framework import GlobalContext, PluginManager, ToolPostInvokePayload, ToolPreInvokePayload

from tests.test_tr_pii import make_tckn


async def test_manager_loads_telveguard_and_enforces():
    mgr = PluginManager("contextforge/plugins-telveguard.yaml")
    await mgr.initialize()
    gctx = GlobalContext(request_id="it-1")

    tckn = make_tckn()
    res, _ = await mgr.invoke_hook(
        "tool_post_invoke",
        ToolPostInvokePayload(name="crm_lookup", result={"content": [{"type": "text", "text": f"TC {tckn}"}]}),
        gctx,
    )
    assert tckn not in res.modified_payload.result["content"][0]["text"]

    res, _ = await mgr.invoke_hook(
        "tool_pre_invoke",
        ToolPreInvokePayload(name="email_send", args={"body": f"Kimlik: {tckn}"}),
        gctx,
    )
    assert res.continue_processing is False
    assert res.violation.code == "TELVEGUARD_PII_EXFILTRATION"
    await mgr.shutdown()


async def test_manager_placeholders_consistent_when_contexts_carried():
    """ContextForge context tablosunu geri verirse yer tutucular çağrılar arası tutarlı."""
    mgr = PluginManager("contextforge/plugins-telveguard.yaml")
    await mgr.initialize()
    gctx = GlobalContext(request_id="it-2")
    t1, t2 = make_tckn(seed=1), make_tckn(seed=2)

    def payload(text):
        return ToolPostInvokePayload(name="crm_lookup", result={"content": [{"type": "text", "text": text}]})

    def text_of(res):
        return res.modified_payload.result["content"][0]["text"]

    res, contexts = await mgr.invoke_hook("tool_post_invoke", payload(f"A {t1}"), gctx)
    assert text_of(res) == "A [TCKN_1]"
    res, contexts = await mgr.invoke_hook("tool_post_invoke", payload(f"B {t2}"), gctx,
                                          local_contexts=contexts)
    assert text_of(res) == "B [TCKN_2]"
    res, _ = await mgr.invoke_hook("tool_post_invoke", payload(f"C {t1}"), gctx,
                                   local_contexts=contexts)
    assert text_of(res) == "C [TCKN_1]"
    assert t1 not in repr(gctx.state)

    # Tablo taşınmazsa yeni istek gibi davranır (numaralandırma baştan)
    res, _ = await mgr.invoke_hook("tool_post_invoke", payload(f"D {t2}"), gctx)
    assert text_of(res) == "D [TCKN_1]"
    await mgr.shutdown()
