"""Tests for YAML rule loading."""

from pathlib import Path

from linux_hardening_advisor.models.rules import CheckType
from linux_hardening_advisor.static.rules_loader import load_rules_from_directory

_EXPECTED_CIS_IDS = frozenset(
    {
        "UBTU-24-100010",
        "UBTU-24-100020",
        "UBTU-24-100030",
        "UBTU-24-100040",
        "UBTU-24-100200-install",
        "UBTU-24-100200-enabled",
        "UBTU-24-100200-active",
        "UBTU-24-100300",
        "UBTU-24-100310",
        "UBTU-24-100500",
        "UBTU-24-100510-enabled",
        "UBTU-24-100510-active",
        "UBTU-24-100600",
        "UBTU-24-100650",
        "UBTU-24-100660-enabled",
        "UBTU-24-100660-active",
        "UBTU-24-100800",
        "UBTU-24-100810-enabled",
        "UBTU-24-100810-active",
        "UBTU-24-100830",
        "UBTU-24-102000",
        "UBTU-24-102010",
        "UBTU-24-300006",
        "UBTU-24-400110",
        "UBTU-24-400220",
    }
)


def test_load_ubtu_cis_rules(rules_cis_dir: Path):
    rules = load_rules_from_directory(rules_cis_dir, recursive=False)
    by_id = {r.id: r for r in rules}
    assert set(by_id.keys()) == _EXPECTED_CIS_IDS

    r10 = by_id["UBTU-24-100010"]
    assert r10.section == "1.2"
    assert r10.check_type == CheckType.COMMAND_OUTPUT_CONTAINS
    assert r10.verification_command and "systemd-timesyncd" in r10.verification_command

    r20 = by_id["UBTU-24-100020"]
    assert r20.section == "1.3"
    assert r20.check_type == CheckType.COMMAND_OUTPUT_CONTAINS
    assert r20.verification_command and "grep ntp" in r20.verification_command
    assert "apt-get purge ntp" in r20.recommendation

    r30 = by_id["UBTU-24-100030"]
    assert r30.section == "1.4"
    assert r30.check_type == CheckType.COMMAND_OUTPUT_CONTAINS
    assert r30.verification_command and "grep telnetd" in r30.verification_command
    assert "apt-get remove telnetd" in r30.recommendation

    r40 = by_id["UBTU-24-100040"]
    assert r40.section == "1.5"
    assert r40.check_type == CheckType.COMMAND_OUTPUT_CONTAINS
    assert "grep rsh-server" in (r40.verification_command or "")
    assert "apt-get remove rsh-server" in r40.recommendation

    r_inst = by_id["UBTU-24-100200-install"]
    assert r_inst.section == "1.10"
    assert r_inst.check_type == CheckType.COMMAND_OUTPUT_NOT_CONTAINS
    assert "grep rsyslog" in (r_inst.verification_command or "")
    assert "apt-get install rsyslog" in r_inst.recommendation

    r_en = by_id["UBTU-24-100200-enabled"]
    assert r_en.check_type == CheckType.SERVICE_ENABLED
    assert r_en.target.get("service") == "rsyslog.service"

    r_ac = by_id["UBTU-24-100200-active"]
    assert r_ac.check_type == CheckType.SERVICE_ACTIVE
    assert r_ac.target.get("service") == "rsyslog.service"

    r_fw = by_id["UBTU-24-100300"]
    assert r_fw.section == "1.11"
    assert r_fw.check_type == CheckType.COMMAND_OUTPUT_NOT_CONTAINS
    assert "grep ufw" in (r_fw.verification_command or "")
    assert "apt install -y ufw" in r_fw.recommendation

    assert by_id["UBTU-24-100310"].section == "1.12"
    assert by_id["UBTU-24-100500"].section == "1.16"
    assert by_id["UBTU-24-100510-enabled"].target.get("service") == "apparmor.service"
    assert by_id["UBTU-24-100650"].section == "1.19"
    assert by_id["UBTU-24-100660-enabled"].target.get("service") == "sssd.service"
    assert by_id["UBTU-24-100800"].section == "1.22"
    assert by_id["UBTU-24-100810-enabled"].target.get("service") == "ssh.service"
    assert by_id["UBTU-24-102000"].section == "1.32"
    assert by_id["UBTU-24-102010"].section == "1.33"
    assert by_id["UBTU-24-300006"].section == "1.53"
    assert by_id["UBTU-24-400110"].section == "1.81"
    assert by_id["UBTU-24-400220"].section == "1.82"


def test_load_project_rules_includes_cis(project_root: Path):
    rules = load_rules_from_directory(project_root / "rules", recursive=True)
    ids = {r.id for r in rules}
    assert ids >= _EXPECTED_CIS_IDS


def test_examples_dir_can_be_empty(rules_examples_dir: Path):
    rules = load_rules_from_directory(rules_examples_dir, recursive=False)
    assert rules == []
