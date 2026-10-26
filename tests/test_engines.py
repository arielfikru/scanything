from scanything.engines import GENERIC_DET_RE, vt_signals


def vt(dets, total=70):
    names = list(dets.values())
    return {"found": True, "malicious": len(dets), "engines_total": total, "detections": dets,
            "generic_detections": sum(bool(GENERIC_DET_RE.search(n)) for n in names),
            "pua_detections": 0, "threat_label": None}


def test_low_generic_detections_look_like_false_positive():
    s = vt_signals(vt({"Microsoft": "Trojan:Win32/Wacatac.B!ml", "SecureAge": "Generic.ML"}))
    assert s[0]["id"] == "vt_low_generic"


def test_many_named_detections_are_high():
    s = vt_signals(vt({f"E{i}": "Win32.RedLineStealer" for i in range(12)}))[0]
    assert (s["id"], s["severity"]) == ("vt_detected", "high")


def test_not_found_and_clean():
    assert vt_signals({"found": False})[0]["id"] == "vt_unknown"
    assert vt_signals(vt({}))[0]["id"] == "vt_clean"
    assert vt_signals({"error": "HTTP 401"}) == []
