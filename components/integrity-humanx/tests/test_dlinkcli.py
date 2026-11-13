"""dlinkcli whitelist and parsers with invented D-Link transcripts (no telnet session is opened)."""
import re

import pytest

import dlinkcli as D


def mac(n):
    """Invented locally administered MAC, built at run time."""
    return "-".join(["02", "00", "00", "00", "00", "%02X" % n])


@pytest.mark.parametrize("cmd", ["show switch", "show stp ports 1-4", "show ports 1 description", "show fdb port 3", "show log",
                                 "show erps raps_vlan 100", "show ddm ports 1-2 status", "show  vlan   vlanid 100",
                                 "show stp mst_config_id", "show log index 1-50", 'show config current_config include "erps"'])
def test_allowed_reads(cmd):
    assert D.allowed(cmd)


@pytest.mark.parametrize("cmd", ["config stp ports 1 state disable", "show config current_config", "show account", "show snmp",
                                 'show config current_config include "snmp"', "show users", "show ssh", "reboot", "save",
                                 "show switch; reboot", "enable clipaging", "show cable_diag ports 1", "show log index 99999"])
def test_refused_commands(cmd):
    assert not D.allowed(cmd)


def test_ring_config_only_keeps_protection_lines():
    text = ("Command: show config current_config include \"stp\"\n"
            "config stp version rstp\n"
            "create account admin operator\n"
            "config snmp community x\n"
            "enable stp\n")
    out = D.ring_config_only(text)
    assert "config stp version rstp" in out and "enable stp" in out
    assert "account" not in out and "snmp" not in out
    assert "строк stp/erps/loopdetect" in D.ring_config_only("Command: x\nconfig vlan v1 add 1")


SWITCH = re.sub(r"<MAC([0-9A-F]{2})>", lambda x: mac(int(x.group(1), 16)), """Command: show switch

Device Type        : DES-3028 Fast Ethernet Switch
MAC Address        : <MAC0A>
IP Address         : 198.51.100.5 (Manual)
Firmware Version   : Build 2.91.B01
Hardware Version   : A2
System Uptime      : 1 days, 2 hours, 3 minutes, 4 seconds
Spanning Tree      : Enabled
Telnet             : Enabled (TCP 23)
CLI Paging         : Enabled
""")
STP = "STP Status        : Enabled\nSTP Version       : RSTP\nMax Age           : 20\nForwarding BPDU   : Disabled\n"
STP_PORTS = re.sub(r"<MAC([0-9A-F]{2})>", lambda x: mac(int(x.group(1), 16)), """Port Index    : 1
Connection    : Link Up
External PathCost : Auto/200000 , Edge Port : False/No , P2P : Auto/Yes
Port STP      : Enabled , Restricted Role : False, Restricted TCN : False
Port Forward BPDU : Disabled
 MSTI   Designated Bridge   Internal PathCost  Prio  Status      Role
 0      8000/<MAC01>  200000      128   Forwarding  Root
Port Index    : 2
Port STP      : Disabled
""")
PORTS = """ Port   State/          Settings             Connection           Address
        MDI             Speed/Duplex/FlowCtrl Speed/Duplex/FlowCtrl Learning
 1      Enabled         Auto/Disabled        100M/Full/None       Enabled
 2      Enabled         Auto/Disabled        LinkDown             Enabled
 25(C)  Enabled         Auto/Disabled        LinkDown             Enabled
"""
FDB = re.sub(r"<MAC([0-9A-F]{2})>", lambda x: mac(int(x.group(1), 16)), """VID  VLAN Name                        MAC Address       Port Type
---- -------------------------------- ----------------- ---- ---------------
100  ring100                          <MAC11> 1    Dynamic
100  ring100                          <MAC12> 1    Dynamic
200  ring200                          <MAC13> 2    Dynamic
""")
VLAN = """VID             : 100        VLAN Name       : ring100
VLAN Type       : Static     Advertisement   : Disabled
Member Ports    : 1-2
Current Tagged Ports   : 1-2
Current Untagged Ports :
"""
TRAFFIC = " 1     100000    Enabled   Disabled  Disabled  drop\n 2     100000    Disabled  Disabled  Disabled  drop\n"


def test_summarise_invented_transcripts():
    res = D.summarise({"show switch": SWITCH, "show stp": STP, "show stp ports": STP_PORTS, "show ports": PORTS,
                       "show fdb": FDB, "show vlan": VLAN, "show traffic control": TRAFFIC})
    assert res["device"]["type"].startswith("DES-3028") and res["device"]["firmware"] == "Build 2.91.B01"
    assert res["stp"]["status"] == "Enabled" and res["stp"]["forwarding_bpdu"] == "Disabled"
    sp = {x["port"]: x for x in res["stp_ports"]}
    assert sp[1]["port_stp"] == "Enabled" and sp[1]["msti"][0]["status"] == "Forwarding" and sp[2]["port_stp"] == "Disabled"
    ports = {x["port"]: x for x in res["ports"]}
    assert ports[1]["link_up"] and not ports[2]["link_up"] and ports[25]["medium"] == "copper"
    assert res["fdb"]["entries"] == 3 and res["fdb"]["per_port"] == {"1": 2, "2": 1}
    assert res["vlans"][0]["vid"] == 100 and res["vlans"][0]["tagged"] == "1-2"
    assert res["storm"]["broadcast_enabled_ports"] == [1]
    assert res["uplink_candidates"]["tagged_ports"] == [1, 2]
    text = D.render_summary(res)
    assert "DES-3028" in text and "Links up : 1:100M/Full/None" in text


def test_clean_and_ports_list():
    assert D.clean("show switch\r\n\x1b[1mline\x1b[0m\r\n\r\n\r\nnext\r\nDES-3028:admin# ", "show switch") == "line\n\nnext"
    assert D.ports_list("1-3,5") == [1, 2, 3, 5] and D.ports_list("") == []


def test_profile_falls_back_to_default(tmp_path, monkeypatch):
    monkeypatch.setattr(D, "PROFILE_MAP", tmp_path / "profiles.json")
    assert D.profile_for_target("198.51.100.5") == "default"
    (tmp_path / "profiles.json").write_text('{"targets": {"198.51.100.5": "dlink-des-legacy"}}', encoding="utf-8")
    assert D.profile_for_target("198.51.100.5") == "dlink-des-legacy"


def test_mask_removes_secret_pieces():
    secret = b"pw-" + b"x1y2z3"
    out = D._mask(b"login ok pw-x1y2z3 and echo y2z3 here", secret)
    assert secret not in out and b"y2z3" not in out
