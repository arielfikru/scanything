import copy
import hashlib
import json
import subprocess
import sys

from scanything.engines import vt_signals
from scanything.ids import RULESET, make_verdict, scan_id_of
from tests.conftest import scan_bytes
from tests.fixtures import make_pe, make_zip

SAMPLE = make_zip({"invoice.pdf.exe": make_pe(strings=b"\x00vssadmin delete shadows /all\x00")})


def test_same_file_same_ids():
    a, b = scan_bytes("mail.zip", SAMPLE), scan_bytes("mail.zip", SAMPLE)
    assert a["ids"] == b["ids"]
    assert a["ids"]["file_id"] == hashlib.sha256(SAMPLE).hexdigest()
    assert a["ids"]["scan_id"].startswith("scn_") and len(a["ids"]["scan_id"]) == 28
    assert a["ids"]["ruleset"] == RULESET


def test_scan_id_is_recomputable_from_the_json_report():
    r = scan_bytes("mail.zip", SAMPLE)
    r.pop("_scan")
    loaded = json.loads(json.dumps(r))
    assert scan_id_of(loaded) == r["ids"]["scan_id"]


def test_volatile_enrichment_does_not_change_scan_id():
    r = scan_bytes("mail.zip", SAMPLE)
    before = r["ids"]["scan_id"]
    r2 = copy.deepcopy({k: v for k, v in r.items() if k != "_scan"})
    vt = {"found": True, "malicious": 0, "engines_total": 70, "detections": {}, "generic_detections": 0,
          "pua_detections": 0}
    r2["files"][1]["virustotal"] = vt
    r2["files"][1]["signals"] += vt_signals(vt)
    r2["files"][1]["score"] += 99
    r2["generated"] = "2099-01-01T00:00:00+00:00"
    r2["target"]["path"] = "/somewhere/else/mail.zip"
    assert scan_id_of(r2) == before


def test_name_changes_scan_id_but_not_file_id():
    a, b = scan_bytes("mail.zip", SAMPLE), scan_bytes("renamed.zip", SAMPLE)
    assert a["ids"]["file_id"] == b["ids"]["file_id"]
    assert a["ids"]["scan_id"] != b["ids"]["scan_id"]


def test_tampered_report_no_longer_matches():
    r = scan_bytes("mail.zip", SAMPLE)
    r.pop("_scan")
    r["files"][1]["signals"] = []
    assert scan_id_of(r) != r["ids"]["scan_id"]


def test_scan_id_stable_across_processes(tmp_path):
    f = tmp_path / "mail.zip"
    f.write_bytes(SAMPLE)
    ids = []
    for _ in range(2):
        out = tmp_path / "r.json"
        subprocess.run([sys.executable, "-m", "scanything", str(f), "--no-llm", "--json-out", str(out)],
                       check=True, capture_output=True)
        ids.append(json.loads(out.read_text())["ids"]["scan_id"])
    assert ids[0] == ids[1] == scan_bytes("mail.zip", SAMPLE)["ids"]["scan_id"]


def test_verdict_record():
    text = "## Verdict: LIKELY FALSE POSITIVE (confidence 80%)\n**Why** ..."
    v = make_verdict("scn_x", "netra", "m", text, "2026-10-26T00:00:00+00:00")
    assert (v["label"], v["confidence"], v["scan_id"]) == ("LIKELY_FALSE_POSITIVE", 80, "scn_x")
    assert v["verdict_id"].startswith("vrd_")
    assert make_verdict("scn_x", "netra", "m", text + " ", "later")["verdict_id"] != v["verdict_id"]
    assert make_verdict("scn_x", "netra", "m", text, "later")["verdict_id"] == v["verdict_id"]
    assert make_verdict("scn_x", "netra", "m", "no format", "t")["label"] is None
    pua = make_verdict("s", "p", "m", "## Verdict: **PUA/GREYWARE** (confidence 60%)", "t")
    assert pua["label"] == "PUA_GREYWARE"
