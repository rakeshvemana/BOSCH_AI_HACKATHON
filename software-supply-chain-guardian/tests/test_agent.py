"""Triage agent tests: a scripted fake model replaces the LLM, so no network or API key is needed."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.main import create_app
from backend.services import agent_service
from backend.services.discovery_service import discover_uploads
from backend.services.storage_service import AnalysisStore
from tests.conftest import read_sample


def _result():
    res, _ = discover_uploads(read_sample("suspicious-sample", "package.json", "package-lock.json", "ci.yml"))
    assert res.findings
    return res


def _tool_call(name, args, cid="c1"):
    return {"role": "assistant", "content": None,
            "tool_calls": [{"id": cid, "type": "function", "function": {"name": name, "arguments": json.dumps(args)}}]}


class Scripted:
    def __init__(self, *replies):
        self.replies, self.calls = list(replies), []

    def __call__(self, messages, tools):
        self.calls.append((list(messages), tools))
        return self.replies.pop(0)


def test_agent_uses_tools_and_validates_output():
    res = _result()
    f = res.findings[0]
    final = {"role": "assistant", "content": "```json\n" + json.dumps({"summary": "ok", "items": [
        {"finding_id": f.id, "verdict": "real-risk", "adjusted_risk": "critical", "reasoning": "r", "fix": "x"},
        {"finding_id": "invented", "verdict": "real-risk", "adjusted_risk": "low", "reasoning": "r"},
        ]}) + "\n```"}
    llm = Scripted(_tool_call("get_finding", {"finding_id": f.id}), final)
    report = agent_service.run_triage(res, llm, "fake")
    assert [s.tool for s in report.steps] == ["get_finding"]
    # the tool result was fed back to the model
    assert llm.calls[1][0][-1]["role"] == "tool" and f.id in llm.calls[1][0][-1]["content"]
    ids = [i.finding_id for i in report.items]
    assert "invented" not in ids
    assert len(ids) == report.findings_considered  # skipped findings are still listed
    first = report.items[0]
    assert (first.finding_id, first.verdict, first.original_risk, first.adjusted_risk) == (f.id, "real-risk", f.risk, "critical")
    assert all(i.verdict == "needs-review" for i in report.items[1:])


def test_agent_never_modifies_findings_and_handles_bad_values():
    res = _result()
    before = res.model_dump_json()
    f = res.findings[0]
    llm = Scripted({"role": "assistant", "content": json.dumps({"summary": "s", "items": [
        {"finding_id": f.id, "verdict": "ignore-it", "adjusted_risk": "banana", "reasoning": "r"}]})})
    report = agent_service.run_triage(res, llm, "fake")
    assert res.model_dump_json() == before
    assert report.items[0].verdict == "needs-review" and report.items[0].adjusted_risk == f.risk


def test_step_budget_forces_a_final_answer_without_tools():
    res = _result()
    llm = Scripted(_tool_call("get_changes", {}), {"role": "assistant", "content": '{"summary": "forced", "items": []}'})
    report = agent_service.run_triage(res, llm, "fake", max_steps=1)
    assert report.summary == "forced"
    assert llm.calls[-1][1] is None  # last call offered no tools


def test_unknown_tool_and_bad_args_are_contained():
    box = agent_service.Toolbox(_result())
    assert "error" in box.call("delete_everything", {})
    assert "error" in box.call("get_finding", {"wrong": 1})
    assert "error" in box.call("get_component", {"name": "does-not-exist"})


def test_dependency_path_tool_reaches_a_flagged_component():
    res = _result()
    name = next(f.component_name for f in res.findings if f.component_name)
    out = agent_service.Toolbox(res).call("get_dependency_paths", {"name": name})
    assert isinstance(out, dict) and any(out.values())


def test_garbage_answer_is_a_clean_error():
    with pytest.raises(agent_service.LLMError):
        agent_service.run_triage(_result(), Scripted({"role": "assistant", "content": "I cannot help"}), "fake")


def test_no_findings_means_no_llm_call():
    res = _result()
    res.findings = []
    llm = Scripted()
    assert agent_service.run_triage(res, llm, "fake").items == [] and llm.calls == []


def test_endpoint_without_key_is_503(tmp_path, monkeypatch):
    monkeypatch.delenv("DEEPSEEK_API_KEY", raising=False)
    app = create_app(store=AnalysisStore(tmp_path / "a.db"))
    c = TestClient(app)
    files = [("files", (n, d, "application/octet-stream")) for n, d in
             read_sample("suspicious-sample", "package.json", "package-lock.json").items()]
    aid = c.post("/api/discover/file", files=files).json()["analysis_id"]
    r = c.post(f"/api/discovery/{aid}/triage")
    assert r.status_code == 503 and "DEEPSEEK_API_KEY" in r.json()["detail"]


def test_endpoint_with_injected_llm(tmp_path):
    llm = Scripted({"role": "assistant", "content": '{"summary": "done", "items": []}'})
    c = TestClient(create_app(store=AnalysisStore(tmp_path / "a.db"), llm=llm))
    files = [("files", (n, d, "application/octet-stream")) for n, d in
             read_sample("suspicious-sample", "package.json", "package-lock.json").items()]
    aid = c.post("/api/discover/file", files=files).json()["analysis_id"]
    r = c.post(f"/api/discovery/{aid}/triage")
    assert r.status_code == 200 and r.json()["summary"] == "done"


def test_deepseek_client_maps_errors():
    import httpx
    def handler(status):
        return agent_service.DeepSeekClient("k", http=httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(status))))
    for status, word in ((401, "API key"), (402, "balance"), (429, "rate"), (500, "500")):
        with pytest.raises(agent_service.LLMError, match=word):
            handler(status)([], None)
    ok = httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(
        200, json={"choices": [{"message": {"role": "assistant", "content": "hi"}}]})))
    assert agent_service.DeepSeekClient("k", http=ok)([], None)["content"] == "hi"
