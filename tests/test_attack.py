import re

from scanything import static
from scanything.attack import SIGNAL_MAP, TECHNIQUES, annotate, summarize


def test_every_mapped_technique_is_defined_and_well_formed():
    for sid, tids in SIGNAL_MAP.items():
        for tid in tids:
            assert tid in TECHNIQUES, (sid, tid)
            assert re.fullmatch(r"T\d{4}(\.\d{3})?", tid)


def test_string_rules_with_real_behaviour_are_mapped():
    unmapped_ok = {"eicar_test_file", "prompt_injection"}
    for sid, *_ in static.SUS_PATTERNS:
        assert sid in SIGNAL_MAP or sid in unmapped_ok, sid


def test_annotate_and_summarize():
    files = [{"index": 0, "signals": [{"id": "shadow_copy_delete"}, {"id": "unsigned"}]},
             {"index": 1, "signals": [{"id": "ransom_note"}, {"id": "shadow_copy_delete"}]}]
    for f in files:
        annotate(f["signals"])
    assert files[0]["signals"][0]["attack"] == ["T1490"]
    assert "attack" not in files[0]["signals"][1]
    summary = summarize(files)
    assert [t["id"] for t in summary] == ["T1486", "T1490"]
    assert summary[1] == {"id": "T1490", "name": "Inhibit System Recovery", "tactic": "Impact",
                          "evidence": ["#0 shadow_copy_delete", "#1 shadow_copy_delete"]}
