import pytest

from cve_triage import ssvc
from cve_triage.policy import Policy, delivery_decision


def test_tables_are_complete():
    assert len(ssvc.coordinator_table()) == 36
    assert len(ssvc.bod_table()) == 16
    assert set(ssvc.coordinator_table().values()) == set(ssvc.DECISIONS)
    assert set(ssvc.bod_table().values()) == set(ssvc.BOD_TIMELINES)


@pytest.mark.parametrize(
    "inputs, expected",
    [
        (("active", "yes", "total", "high"), "act"),
        (("active", "no", "total", "medium"), "attend"),
        (("poc", "no", "total", "medium"), "track*"),
        (("none", "yes", "total", "high"), "attend"),
        (("none", "no", "partial", "low"), "track"),
    ],
)
def test_coordinator_decision(inputs, expected):
    assert ssvc.coordinator_decision(*inputs) == expected


@pytest.mark.parametrize(
    "mp, wb, expected",
    [
        ("minimal", "minimal", "low"),
        ("support", "minimal", "medium"),
        ("support", "material", "medium"),
        ("minimal", "material", "medium"),  # undefined by CISA, conservative choice
        ("essential", "minimal", "high"),
        ("minimal", "irreversible", "high"),
    ],
)
def test_mission_wellbeing(mp, wb, expected):
    assert ssvc.mission_wellbeing(mp, wb) == expected


def test_bod_timeline():
    assert ssvc.bod_timeline(True, True, "yes", "total") == "3 days & forensic investigation"
    assert ssvc.bod_timeline(False, False, "no", "partial") == "fix on system upgrade"
    assert ssvc.bod_timeline(False, True, "yes", "total") == "3 days"


def test_policy_mapping_and_escalations():
    p = Policy()
    assert delivery_decision("track*", "60 days", None, p)[0] == "ATTEND"
    assert delivery_decision("track", "3 days", None, p)[0] == "ACT"
    assert delivery_decision("track", "14 days", None, p)[0] == "ATTEND"
    assert delivery_decision("track", "60 days", 0.5, p)[0] == "ATTEND"
    assert delivery_decision("track", "60 days", 0.01, p)[0] == "TRACK"
    decision, reasons = delivery_decision("track", "60 days", 0.5, p)
    assert len(reasons) == 2 and "EPSS" in reasons[1]


def test_policy_from_dict_rejects_bad_values():
    with pytest.raises(ValueError):
        Policy.from_dict({"decision_mapping": {"act": "NOW"}})
    p = Policy.from_dict({"escalations": {"epss_attend_threshold": None, "bod_3_days_to_act": False}})
    assert delivery_decision("track", "3 days", 0.9, p)[0] == "TRACK"
