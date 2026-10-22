"""Windows account-manipulation, defence-tampering and service-baseline rules (added in v1.3)."""
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import config  # noqa: E402
import correlate  # noqa: E402
import normalize  # noqa: E402


def _ev(eid, data, channel="Security", provider="Microsoft-Windows-Security-Auditing", t="2026-09-20T10:00:00.000Z"):
    d = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event><System><Provider Name="{provider}"/><EventID>{eid}</EventID><TimeCreated SystemTime="{t}"/>'
            f"<Channel>{channel}</Channel><Computer>dc01.lab.local</Computer></System><EventData>{d}</EventData></Event>")


def _flags(*events):
    with tempfile.TemporaryDirectory() as tmp:
        p = os.path.join(tmp, "windows_security.xml")
        with open(p, "w", encoding="utf-8") as f:
            f.write("<Events>" + "".join(events) + "</Events>")
        ev, st = normalize.parse_windows(p)
    correlate.detect(ev, dict(config.DEFAULT_CASE))
    return [(e["event_type"], sorted(e["flags"])) for e in ev], st


class AccountManipulation(unittest.TestCase):
    def test_uac_weakened_spn_rename_reset_and_sensitive_group(self):
        res, st = _flags(
            _ev(4738, {"SubjectUserName": "admin", "TargetUserName": "svc1", "UserAccountControl": "%%2096", "ServicePrincipalNames": "-", "AllowedToDelegateTo": "-"}),
            _ev(4738, {"SubjectUserName": "admin", "TargetUserName": "svc2", "UserAccountControl": "%%2094", "ServicePrincipalNames": "-", "AllowedToDelegateTo": "-"}),
            _ev(5136, {"SubjectUserName": "admin", "ObjectDN": "CN=web,DC=lab", "AttributeLDAPDisplayName": "servicePrincipalName", "AttributeValue": "HTTP/web"}),
            _ev(4781, {"SubjectUserName": "admin", "OldTargetUserName": "pc-88$", "NewTargetUserName": "dc01"}),
            _ev(4724, {"SubjectUserName": "admin", "TargetUserName": "bob"}),
            _ev(4728, {"SubjectUserName": "admin", "TargetUserName": "Domain Admins", "MemberName": "CN=eve"}),
            _ev(4728, {"SubjectUserName": "admin", "TargetUserName": "Marketing", "MemberName": "CN=eve"}))
        self.assertEqual(st["errors"], 0)
        flags = [f for _, f in res]
        self.assertIn("account_security_weakened", flags[0])        # 'Don't Require Preauth' switched on
        self.assertEqual(flags[1], [])                              # 'Not Delegated' is a hardening, not a weakening
        self.assertIn("delegation_or_spn_set", flags[2])
        self.assertIn("suspicious_account_rename", flags[3])        # computer account loses its trailing $
        self.assertIn("password_reset_by_other", flags[4])
        self.assertIn("privilege_group_add", flags[5])              # privileged group, even without an untrusted session
        self.assertEqual(flags[6], [])                              # ordinary group


class DefenceTampering(unittest.TestCase):
    def test_defender_and_sysmon_tampering(self):
        res, _ = _flags(
            _ev(4688, {"SubjectUserName": "admin", "NewProcessName": "C:\\Windows\\System32\\sc.exe", "CommandLine": "sc  config WinDefend start= disabled"}),
            _ev(4104, {"ScriptBlockText": "Set-MpPreference -DisableRealtimeMonitoring $true"}, channel="Microsoft-Windows-PowerShell/Operational",
                provider="Microsoft-Windows-PowerShell"),
            _ev(5007, {"New Value": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\TOOLS = 0x0"},
                channel="Microsoft-Windows-Windows Defender/Operational", provider="Microsoft-Windows-Windows Defender"),
            _ev(4104, {"ScriptBlockText": "Get-MpPreference | Select DisableRealtimeMonitoring"}, channel="Microsoft-Windows-PowerShell/Operational",
                provider="Microsoft-Windows-PowerShell"))
        flags = [f for _, f in res]
        for i in range(3):
            self.assertIn("defender_tampering", flags[i])
        self.assertNotIn("defender_tampering", flags[3])             # only reading the settings is not tampering


class ServiceBaseline(unittest.TestCase):
    def test_routine_driver_installs_are_not_alerts(self):
        res, _ = _flags(
            _ev(7045, {"ServiceName": "netvsc", "ImagePath": "system32\\DRIVERS\\netvsc60.sys", "AccountName": ""}, channel="System",
                provider="Service Control Manager"),
            _ev(7045, {"ServiceName": "Hyper-V Heartbeat", "ImagePath": "%SystemRoot%\\system32\\vmicsvc.exe -feature Heartbeat", "AccountName": ""},
                channel="System", provider="Service Control Manager"),
            _ev(7045, {"ServiceName": "x7Kd2", "ImagePath": "%COMSPEC% /b /c start /b /min powershell -nop -w hidden -e aQBlAHgA", "AccountName": ""},
                channel="System", provider="Service Control Manager"),
            _ev(7045, {"ServiceName": "PSEXESVC", "ImagePath": "%SystemRoot%\\PSEXESVC.exe", "AccountName": ""}, channel="System",
                provider="Service Control Manager"))
        flags = [f for _, f in res]
        self.assertEqual(flags[0], [])
        self.assertEqual(flags[1], [])
        self.assertIn("service_installed", flags[2])
        self.assertIn("service_installed", flags[3])


if __name__ == "__main__":
    unittest.main()
