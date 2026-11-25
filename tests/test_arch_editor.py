import pandas as pd

from core.offline_client import OfflineClient
from core.workflow import analyze_architecture, run_pipeline
from dashboard import arch_editor
from tests.test_offline import DOC, processed


def draft():
    return analyze_architecture(OfflineClient(), processed())


def frames(arch):
    return arch_editor.components_frame(arch), arch_editor.flows_frame(arch)


def test_unchanged_tables_keep_the_architecture_and_mark_it_reviewed():
    arch = draft()
    built, errors = arch_editor.build_architecture(arch, *frames(arch))
    assert not errors and built.component_names() == arch.component_names()
    assert len(built.data_flows) == len(arch.data_flows)
    assert all(not c.needs_review and c.basis == "stated" for c in built.components)
    assert arch_editor.REVIEWED_NOTE in built.assumptions
    assert not any(f.needs_review for f in built.data_flows)


def test_edit_rename_delete_and_add():
    arch = draft()
    comps, flows = frames(arch)
    comps.loc[comps["Name"] == "Orders Database", ["Name", "Sensitive data"]] = ["Customer DB", True]
    comps = comps[comps["Name"] != "Order Service"]
    comps = pd.concat([comps, pd.DataFrame([{"Name": "Audit Log", "Type": "Logging / Monitoring",
                                             "Trust boundary": "Internal", "Sensitive data": False, "Description": ""}])])
    flows = flows[(flows["Source"] != "Order Service") & (flows["Destination"] != "Order Service")]
    flows = pd.concat([flows, pd.DataFrame([{"Source": "API Gateway", "Destination": "Customer DB", "Protocol": "TLS",
                                              "Authenticated": "Yes", "Data": "orders"}])])
    built, errors = arch_editor.build_architecture(arch, comps, flows)
    assert not errors
    names = built.component_names()
    assert "Customer DB" in names and "Orders Database" not in names and "Order Service" not in names
    assert "Audit Log" in names
    added = next(f for f in built.data_flows if f.destination == "Customer DB")
    assert added.authenticated is True and added.protocol == "TLS"
    assert added.crosses_trust_boundary  # DMZ -> Internal, recomputed from the edited boundaries


def test_validation_errors_block_the_run():
    arch = draft()
    comps, flows = frames(arch)
    bad_flows = pd.concat([flows, pd.DataFrame([{"Source": "API Gateway", "Destination": "Ghost", "Protocol": "",
                                                  "Authenticated": "Unknown", "Data": ""}])])
    built, errors = arch_editor.build_architecture(arch, comps, bad_flows)
    assert built is None and any("Ghost" in e for e in errors)
    dup = pd.concat([comps, comps.iloc[[0]]])
    assert any("Duplicate" in e for e in arch_editor.build_architecture(arch, dup, flows)[1])
    built, errors = arch_editor.build_architecture(arch, comps.iloc[0:0], flows.iloc[0:0])
    assert built is None and any("At least one component" in e for e in errors)


def test_pipeline_uses_the_reviewed_architecture_and_skips_the_stage():
    arch = draft()
    comps, flows = frames(arch)
    comps = comps[comps["Name"] != "Web Frontend"]
    flows = flows[(flows["Source"] != "Web Frontend") & (flows["Destination"] != "Web Frontend")]
    built, _ = arch_editor.build_architecture(arch, comps, flows)
    events = []
    model = run_pipeline(OfflineClient(), processed(), "Demo", use_langgraph=False, architecture=built,
                         on_progress=lambda s, m: events.append(s))
    assert "architecture" not in events and events[0] == "threats"
    assert "Web Frontend" not in model.architecture.component_names()
    assert all(t.affected_component != "Web Frontend" for t in model.threats)
