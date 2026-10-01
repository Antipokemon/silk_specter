"""SILK SPECTER Medium campaign.

Distinct multi-region campaign for validation builds.  The scenario intentionally
uses valid credentials, administrative tooling, cross-region pivots, cloud audit
activity, archive staging, cleanup, and only partial endpoint alerting.

This module does not mark the scenario validated.  Generate it with
``--allow-authoring`` until Splunk TA/CIM validation is complete.
"""
from __future__ import annotations

from datetime import timedelta
import uuid

from core.network import NetworkFlow, NetworkLedger
from renderers import windows, linux, zeek, network_devices, apps


def _iso(dt):
    return dt.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _syslog(dt):
    return dt.strftime("%b %d %H:%M:%S")


def _guid(name):
    return "{" + str(uuid.uuid5(uuid.NAMESPACE_DNS, "asteron-medium:" + name)) + "}"


def _zuid(name):
    return "M" + uuid.uuid5(uuid.NAMESPACE_DNS, "zeek-medium:" + name).hex[:17]


def _add_windows_process(store, t, host, user, image, commandline, parent, key, activity, technique, tags):
    guid = _guid(key)
    store.add(
        key=key,
        activity_id=activity,
        time=_iso(t),
        host=host,
        source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        sourcetype="XmlWinEventLog",
        raw=windows.sysmon_process(
            time=_iso(t),
            record_id=store.record_id_at(host, "Microsoft-Windows-Sysmon/Operational", t),
            computer=host,
            guid=guid,
            pid=4400 + (abs(hash(key)) % 5000),
            image=image,
            commandline=commandline,
            parent_guid=_guid(key + ":parent"),
            parent_pid=1220,
            parent_image=parent,
            user=user,
        ),
        truth_label="malicious",
        technique=technique,
        question_tags=tags,
    )
    store.add(
        key=key + ".4688",
        activity_id=activity,
        time=_iso(t + timedelta(milliseconds=8)),
        host=host,
        source="XmlWinEventLog:Security",
        sourcetype="XmlWinEventLog",
        raw=windows.security_4688(
            time=_iso(t + timedelta(milliseconds=8)),
            record_id=store.record_id_at(host, "Security", t + timedelta(milliseconds=8)),
            computer=host,
            subject_user=user.split("\\")[-1],
            new_pid_hex="0x%X" % (4400 + (abs(hash(key)) % 5000)),
            image=image,
            parent=parent,
            commandline=commandline,
        ),
        truth_label="malicious",
        technique=technique,
        question_tags=tags,
    )
    return guid


def _add_zeek_conn(store, t, sensor, flow, key, activity, technique, tags, service="-"):
    uid = _zuid(flow.flow_id)
    store.add(
        key=key,
        activity_id=activity,
        time=_iso(t),
        host=sensor,
        source="zeek:conn",
        sourcetype="zeek:conn",
        raw=zeek.conn(
            t.timestamp(), uid, flow.src_ip, flow.src_port, flow.dest_ip, flow.dest_port,
            service=service, duration=flow.duration or 0.4,
            orig_bytes=flow.bytes_out or 300, resp_bytes=flow.bytes_in or 900,
            local_orig=flow.src_ip.startswith("10."), local_resp=flow.dest_ip.startswith("10."),
        ),
        truth_label="malicious",
        technique=technique,
        question_tags=tags,
    )
    return uid


def build_campaign(store, ctx, environment):
    ledger = NetworkLedger()

    # Synthetic but stable exercise infrastructure.  Public addresses are normal
    # cloud/VPS space rather than "known bad" documentation ranges so participants
    # have to correlate behavior instead of spotting an obvious IOC.
    campaign = ctx.config["campaign"]
    hosts = campaign["hosts"]
    actor_london = campaign["actor_initial_ip"]
    actor_exfil = campaign["actor_exfil_ip"]
    vpn_public = campaign["vpn_public_ip"]
    uk_jump = hosts["UKLO-JMP-01"]
    uk_dc = hosts["UKLO-DC-01"]
    defr_eng = hosts["DEFR-ENG-APP-03"]
    defr_fs = hosts["DEFR-FS-02"]
    nlam_stage = hosts["NLAM-OPS-LNX-04"]
    ausy_eng = hosts["AUSY-ENG-APP-04"]
    ausy_fs = hosts["AUSY-FS-03"]
    cloud_gitlab = hosts["GITLAB-PROD"]
    cloud_dns = hosts["CLOUD-DNS"]

    # ------------------------------------------------------------------
    # 1. UK VPN access with a valid vendor account.  Several failed attempts
    # precede one successful MFA session, but the account is legitimate and the
    # source is a normal cloud provider address.
    # ------------------------------------------------------------------
    t = ctx.at(0, 18, 12, 4)
    for i in range(3):
        et = t + timedelta(seconds=i * 11)
        store.add(
            key=f"med.vpn.fail.{i}", activity_id="MED-ACCESS-001", time=_iso(et),
            host="UKLO-RADIUS-01", source="radius:auth", sourcetype="radius:auth",
            raw=apps.radius_auth(_iso(et), "UKLO-RADIUS-01", "EU\\svc-fieldops", "UKLO-FW-01", actor_london,
                                 result="Access-Reject", method="MSCHAPv2"),
            truth_label="malicious", technique="T1078", question_tags="vpn,valid_accounts,initial_access",
        )
    et = t + timedelta(seconds=48)
    store.add(
        key="med.vpn.success", activity_id="MED-ACCESS-001", time=_iso(et),
        host="UKLO-RADIUS-01", source="radius:auth", sourcetype="radius:auth",
        raw=apps.radius_auth(_iso(et), "UKLO-RADIUS-01", "EU\\svc-fieldops", "UKLO-FW-01", actor_london,
                             result="Access-Accept", method="EAP-TLS"),
        truth_label="malicious", technique="T1078", question_tags="vpn,valid_accounts,initial_access",
    )
    store.add(
        key="med.vpn.pan", activity_id="MED-ACCESS-001", time=_iso(et),
        host="UKLO-FW-01", source="pan:traffic", sourcetype="pan:traffic",
        raw=network_devices.palo_alto(et.strftime("%Y/%m/%d %H:%M:%S"), "PA-UKLO-001", actor_london,
                                     vpn_public, 51372, 443, "allow", "GLOBALPROTECT-VPN", "untrust", "vpn",
                                     bytes_out=4231, bytes_in=12088, nat_dst=uk_jump),
        truth_label="malicious", technique="T1078", question_tags="vpn,initial_access,nat",
    )

    # A legitimate lookalike session from an approved London ISP address.
    bt = ctx.at(0, 17, 48, 33)
    store.add(
        key="med.vpn.benign", activity_id="MED-BENIGN-VPN-001", time=_iso(bt),
        host="UKLO-RADIUS-01", source="radius:auth", sourcetype="radius:auth",
        raw=apps.radius_auth(_iso(bt), "UKLO-RADIUS-01", "EU\\adm-lchen", "UKLO-FW-01", "81.2.69.142",
                             result="Access-Accept", method="EAP-TLS"),
        truth_label="benign", question_tags="vpn,admin_lookalike",
    )

    # ------------------------------------------------------------------
    # 2. Valid network logon to the UK privileged jump host and quiet discovery.
    # ------------------------------------------------------------------
    t = ctx.at(0, 18, 14, 19)
    store.add(
        key="med.jump.4624", activity_id="MED-ACCESS-002", time=_iso(t), host="UKLO-JMP-01",
        source="XmlWinEventLog:Security", sourcetype="XmlWinEventLog",
        raw=windows.security_4624(time=_iso(t), record_id=store.record_id_at("UKLO-JMP-01", "Security", t),
                                  computer="UKLO-JMP-01", user="svc-fieldops", domain="EU", logon_type=3,
                                  ip="10.52.5.87", port="53111", auth="Kerberos"),
        truth_label="malicious", technique="T1078", question_tags="valid_accounts,jump_host",
    )
    commands = [
        (r"C:\\Windows\\System32\\whoami.exe", "whoami /groups", "T1033", "identity_discovery"),
        (r"C:\\Windows\\System32\\nltest.exe", "nltest /dclist:EU.ASTERON.LOCAL", "T1018", "domain_discovery"),
        (r"C:\\Windows\\System32\\net.exe", "net group \"Domain Admins\" /domain", "T1069.002", "group_discovery"),
        (r"C:\\Windows\\System32\\route.exe", "route print", "T1016", "network_discovery"),
    ]
    for i, (image, cmd, tech, tag) in enumerate(commands):
        _add_windows_process(store, t + timedelta(seconds=18 + i * 31), "UKLO-JMP-01", r"EU\\svc-fieldops",
                             image, cmd, r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                             f"med.jump.discovery.{i}", "MED-DISCOVERY-001", tech, f"discovery,{tag},jump_host")

    # ------------------------------------------------------------------
    # 3. Credential material is accessed with a native Windows DLL invocation.
    # Defender observes it, but this is the only direct endpoint alert in this
    # phase so the finding is a clue, not an oracle.
    # ------------------------------------------------------------------
    t = ctx.at(0, 19, 2, 31)
    cmd = r"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 684 C:\\ProgramData\\diag\\lsass.dmp full"
    _add_windows_process(store, t, "UKLO-JMP-01", r"EU\\svc-fieldops",
                         r"C:\\Windows\\System32\\rundll32.exe", cmd,
                         r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         "med.cred.rundll32", "MED-CRED-001", "T1003.001", "credential_access,native_tools")
    alert_id = "MED-ALERT-7C31"
    store.add(
        key="med.cred.alert", activity_id="MED-CRED-001", time=_iso(t + timedelta(seconds=4)), host="UKLO-JMP-01",
        source="ms:defender:eventhub", sourcetype="ms:defender:eventhub",
        raw=apps.defender_alert_info(_iso(t + timedelta(seconds=4)), alert_id,
                                     "Suspicious process accessed LSASS memory", "Medium", "CredentialAccess", "T1003.001"),
        truth_label="malicious", technique="T1003.001", question_tags="credential_access,defender_detection",
    )
    store.add(
        key="med.cred.evidence", activity_id="MED-CRED-001", time=_iso(t + timedelta(seconds=5)), host="UKLO-JMP-01",
        source="ms:defender:eventhub", sourcetype="ms:defender:eventhub",
        raw=apps.defender_alert_evidence(_iso(t + timedelta(seconds=5)), alert_id,
                                         "Suspicious process accessed LSASS memory", "Medium", "UKLO-JMP-01",
                                         r"EU\\svc-fieldops", "rundll32.exe", r"C:\\Windows\\System32", cmd,
                                         "CredentialAccess", remediation_status="Observed", remediation_action="Alert"),
        truth_label="malicious", technique="T1003.001", question_tags="credential_access,defender_detection",
    )

    # ------------------------------------------------------------------
    # 4. Cross-region WMI pivot UK -> DE.  Zeek, firewalls and endpoint events all
    # share the same tuple so analysts can reconstruct the session.
    # ------------------------------------------------------------------
    t = ctx.at(1, 7, 26, 13)
    wmi = ledger.add_flow(NetworkFlow(
        "MED-FLOW-WMI-001", t, uk_jump, 54912, defr_eng, 135,
        bytes_out=2214, bytes_in=7651, duration=4.8, src_host="UKLO-JMP-01", dest_host="DEFR-ENG-APP-03",
        service="dce_rpc", tags=("wmi", "cross_region"),
    ))
    _add_zeek_conn(store, t, "UKLO-ZEEK-01", wmi, "med.wmi.conn.uk", "MED-LATERAL-001", "T1047", "wmi,lateral_movement,cross_region", "dce_rpc")
    _add_zeek_conn(store, t + timedelta(milliseconds=3), "DEFR-ZEEK-01", wmi, "med.wmi.conn.de", "MED-LATERAL-001", "T1047", "wmi,lateral_movement,cross_region", "dce_rpc")
    uid = _zuid(wmi.flow_id)
    store.add(
        key="med.wmi.rpc", activity_id="MED-LATERAL-001", time=_iso(t + timedelta(milliseconds=11)), host="DEFR-ZEEK-01",
        source="zeek:dce_rpc", sourcetype="zeek:dce_rpc",
        raw=zeek.dce_rpc((t + timedelta(milliseconds=11)).timestamp(), uid, uk_jump, defr_eng,
                         endpoint="IWbemLevel1Login", operation="NTLMLogin"),
        truth_label="malicious", technique="T1047", question_tags="wmi,lateral_movement,cross_region",
    )
    store.add(
        key="med.wmi.asa", activity_id="MED-LATERAL-001", time=_iso(t), host="DEFR-FW-01",
        source="cisco:asa", sourcetype="cisco:asa",
        raw=network_devices.cisco_asa(t.strftime("%b %d %Y %H:%M:%S"), "DEFR-FW-01", "302013",
                                     uk_jump, 54912, defr_eng, 135),
        truth_label="malicious", technique="T1047", question_tags="wmi,lateral_movement,cross_region",
    )
    store.add(
        key="med.wmi.logon", activity_id="MED-LATERAL-001", time=_iso(t + timedelta(seconds=2)), host="DEFR-ENG-APP-03",
        source="XmlWinEventLog:Security", sourcetype="XmlWinEventLog",
        raw=windows.security_4624(time=_iso(t + timedelta(seconds=2)),
                                  record_id=store.record_id_at("DEFR-ENG-APP-03", "Security", t + timedelta(seconds=2)),
                                  computer="DEFR-ENG-APP-03", user="svc-engbuild", domain="EU", logon_type=3,
                                  ip=uk_jump, port="54912", auth="NTLM"),
        truth_label="malicious", technique="T1078", question_tags="wmi,lateral_movement,valid_accounts",
    )
    _add_windows_process(store, t + timedelta(seconds=7), "DEFR-ENG-APP-03", r"EU\\svc-engbuild",
                         r"C:\\Windows\\System32\\cmd.exe", r"cmd.exe /c hostname && whoami && dir \\DEFR-FS-02\\Engineering$",
                         r"C:\\Windows\\System32\\wbem\\WmiPrvSE.exe", "med.wmi.remoteproc", "MED-LATERAL-001",
                         "T1047", "wmi,lateral_movement,remote_execution")
    ledger.observe(wmi.flow_id, "zeek")
    ledger.observe(wmi.flow_id, "firewall")
    ledger.observe(wmi.flow_id, "endpoint")
    ledger.require_observations(wmi.flow_id, {"zeek", "firewall", "endpoint"})

    # Benign SCCM WMI lookalike later in the same region.
    bt = ctx.at(1, 9, 5, 0)
    store.add(
        key="med.sccm.lookalike", activity_id="MED-BENIGN-WMI-001", time=_iso(bt), host="DEFR-SCCM-01",
        source="sccm:client", sourcetype="sccm:client",
        raw=apps.sccm_event(_iso(bt), "DFR", "DEFR-ENG-APP-03", r"EU\\svc-sccm", "application_deployment", "success", "EU000771"),
        truth_label="benign", question_tags="wmi,admin_lookalike,sccm",
    )

    # ------------------------------------------------------------------
    # 5. GitLab token use from the compromised DE engineering host and cloud
    # pivot through AWS.  The token is valid and there is no direct malware alert.
    # ------------------------------------------------------------------
    t = ctx.at(1, 8, 3, 49)
    store.add(
        key="med.git.audit", activity_id="MED-CLOUD-001", time=_iso(t), host="GITLAB-PROD",
        source="gitlab:audit", sourcetype="gitlab:audit",
        raw=apps.gitlab_audit(_iso(t), "svc-engbuild", defr_eng, "Project", "repository_download",
                              "asteron/grid-analytics", {"auth_method": "personal_access_token", "archive": "tar.gz"}),
        truth_label="malicious", technique="T1213.003", question_tags="gitlab,collection,valid_token",
    )
    gitflow = ledger.add_flow(NetworkFlow(
        "MED-FLOW-GIT-001", t, defr_eng, 52144, cloud_gitlab, 443,
        bytes_out=4412, bytes_in=18422011, duration=18.4, src_host="DEFR-ENG-APP-03", dest_host="GITLAB-PROD",
        service="ssl", tags=("gitlab", "collection"),
    ))
    uid = _add_zeek_conn(store, t, "DEFR-ZEEK-01", gitflow, "med.git.conn", "MED-CLOUD-001", "T1213.003", "gitlab,collection", "ssl")
    store.add(
        key="med.git.tls", activity_id="MED-CLOUD-001", time=_iso(t + timedelta(milliseconds=9)), host="DEFR-ZEEK-01",
        source="zeek:ssl", sourcetype="zeek:ssl",
        raw=zeek.tls((t + timedelta(milliseconds=9)).timestamp(), uid, defr_eng, 52144, cloud_gitlab, 443,
                     "git.asteron.example", "t13d1517h2_8daaf6152771_02713d6af862"),
        truth_label="malicious", technique="T1213.003", question_tags="gitlab,collection",
    )

    t = ctx.at(1, 8, 37, 14)
    role = "arn:aws:iam::444455556666:role/EngineeringDataReadOnly"
    for i, event_name in enumerate(["AssumeRole", "GetCallerIdentity", "ListBuckets", "ListObjectsV2", "GetObject", "GetSecretValue"]):
        et = t + timedelta(seconds=i * 17)
        store.add(
            key=f"med.aws.{i}", activity_id="MED-CLOUD-002", time=_iso(et), host="AWS-CT-ENGDATA",
            source="aws:cloudtrail", sourcetype="aws:cloudtrail",
            raw=apps.cloudtrail(_iso(et), event_name, defr_eng, role, account="444455556666", region="eu-central-1",
                                user_agent="aws-cli/2.17.4 Python/3.11 Linux/5.15"),
            truth_label="malicious", technique="T1078.004" if i < 2 else "T1530",
            question_tags="aws,cloud,collection,cross_domain",
        )

    # ------------------------------------------------------------------
    # 6. DE file share collection and archive staging.  Deliberate staging is a
    # Medium requirement; 7-Zip activity is corroborated by SMB and endpoint logs.
    # ------------------------------------------------------------------
    t = ctx.at(2, 6, 41, 22)
    smbflow = ledger.add_flow(NetworkFlow(
        "MED-FLOW-SMB-001", t, defr_eng, 53318, defr_fs, 445,
        bytes_out=11902, bytes_in=82377114, duration=92.0, src_host="DEFR-ENG-APP-03", dest_host="DEFR-FS-02",
        service="smb", tags=("collection", "engineering_share"),
    ))
    uid = _add_zeek_conn(store, t, "DEFR-ZEEK-01", smbflow, "med.collect.conn", "MED-COLLECT-001", "T1039", "collection,smb,file_share", "smb")
    for i, name in enumerate(["relay_settings.xlsx", "protection_study.pdf", "substation_inventory.csv", "vpn_peer_matrix.xlsx"]):
        store.add(
            key=f"med.collect.smb.{i}", activity_id="MED-COLLECT-001", time=_iso(t + timedelta(seconds=3 + i * 8)), host="DEFR-ZEEK-01",
            source="zeek:smb_files", sourcetype="zeek:smb_files",
            raw=zeek.smb((t + timedelta(seconds=3 + i * 8)).timestamp(), uid, defr_eng, defr_fs,
                         r"\\DEFR-FS-02\\Engineering$\\GridModernization", name, action="SMB2_READ"),
            truth_label="malicious", technique="T1039", question_tags="collection,smb,file_share",
        )
    archive = r"C:\\ProgramData\\Support\\eu-grid-review.7z"
    _add_windows_process(store, t + timedelta(minutes=3), "DEFR-ENG-APP-03", r"EU\\svc-engbuild",
                         r"C:\\Program Files\\7-Zip\\7z.exe",
                         r'7z.exe a -mx=7 "C:\\ProgramData\\Support\\eu-grid-review.7z" "C:\\ProgramData\\Support\\review\\*"',
                         r"C:\\Windows\\System32\\cmd.exe", "med.stage.7z", "MED-STAGE-001", "T1560.001",
                         "staging,archive,collection")
    store.add(
        key="med.stage.file", activity_id="MED-STAGE-001", time=_iso(t + timedelta(minutes=3, seconds=2)), host="DEFR-ENG-APP-03",
        source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", sourcetype="XmlWinEventLog",
        raw=windows.sysmon_file(time=_iso(t + timedelta(minutes=3, seconds=2)),
                                record_id=store.record_id_at("DEFR-ENG-APP-03", "Microsoft-Windows-Sysmon/Operational", t + timedelta(minutes=3, seconds=2)),
                                computer="DEFR-ENG-APP-03", guid=_guid("med.stage.7z"), pid=7712,
                                image=r"C:\\Program Files\\7-Zip\\7z.exe", target=archive),
        truth_label="malicious", technique="T1074.001", question_tags="staging,archive,file_create",
    )

    # ------------------------------------------------------------------
    # 7. Second-region pivot to Australia with the same service identity.  This
    # makes the participant prove impossible/atypical regional use rather than
    # rely on a single IOC.
    # ------------------------------------------------------------------
    t = ctx.at(2, 13, 18, 7)
    store.add(
        key="med.aus.vpn", activity_id="MED-LATERAL-002", time=_iso(t), host="AUSY-RADIUS-01",
        source="radius:auth", sourcetype="radius:auth",
        raw=apps.radius_auth(_iso(t), "AUSY-RADIUS-01", "EU\\svc-fieldops", "AUSY-FW-01", actor_london,
                             result="Access-Accept", method="EAP-TLS"),
        truth_label="malicious", technique="T1078", question_tags="vpn,valid_accounts,multi_region",
    )
    store.add(
        key="med.aus.forti", activity_id="MED-LATERAL-002", time=_iso(t), host="AUSY-FW-01",
        source="fortigate_traffic", sourcetype="fortigate_traffic",
        raw=network_devices.fortigate(t.strftime("%Y-%m-%d"), t.strftime("%H:%M:%S"), "AUSY-FW-01",
                                     actor_london, ausy_eng, 56214, 443, "accept", 140, "wan", "ssl.root", "HTTPS", 4871, 16220),
        truth_label="malicious", technique="T1078", question_tags="vpn,valid_accounts,multi_region",
    )
    _add_windows_process(store, t + timedelta(minutes=2), "AUSY-ENG-APP-04", r"EU\\svc-fieldops",
                         r"C:\\Windows\\System32\\robocopy.exe",
                         r"robocopy \\AUSY-FS-03\\Engineering$ C:\\ProgramData\\Cache\\AU *.pdf *.xlsx /S /R:1 /W:1",
                         r"C:\\Windows\\System32\\cmd.exe", "med.aus.collect", "MED-COLLECT-002", "T1039",
                         "collection,multi_region,file_share")

    # ------------------------------------------------------------------
    # 8. Staged archive is moved to an NL service host, then uploaded to a cloud
    # VPS.  DLP sees it but only records an allowed-with-justification action.
    # ------------------------------------------------------------------
    t = ctx.at(3, 5, 12, 55)
    store.add(
        key="med.nlam.ssh", activity_id="MED-STAGE-002", time=_iso(t), host="NLAM-OPS-LNX-04",
        source="/var/log/secure", sourcetype="linux_secure",
        raw=linux.secure_auth(_syslog(t), "NLAM-OPS-LNX-04", "svc-transfer", defr_eng, result="Accepted", method="publickey", port=55222),
        truth_label="malicious", technique="T1021.004", question_tags="ssh,lateral_movement,staging",
    )
    for j, line in enumerate(linux.audit_user_auth(epoch=int(t.timestamp()), serial=8300, host="NLAM-OPS-LNX-04",
                                                    user="svc-transfer", src_ip=defr_eng, pid=28411, uid=1007, result="success")):
        store.add(
            key=f"med.nlam.audit.{j}", activity_id="MED-STAGE-002", time=_iso(t + timedelta(milliseconds=j)), host="NLAM-OPS-LNX-04",
            source="/var/log/audit/audit.log", sourcetype="linux_audit", raw=line,
            truth_label="malicious", technique="T1021.004", question_tags="ssh,lateral_movement,staging",
        )
    lt = t + timedelta(minutes=3)
    cmd = "/usr/bin/tar -czf /var/tmp/.cache/sysdiag-20260409.tgz /srv/transfer/incoming/eu-grid-review.7z /srv/transfer/incoming/au-review"
    store.add(
        key="med.nlam.tar", activity_id="MED-STAGE-002", time=_iso(lt), host="NLAM-OPS-LNX-04",
        source="/var/log/syslog", sourcetype="syslog",
        raw=linux.linux_sysmon_process_generic(syslog_time=_syslog(lt), iso_time=_iso(lt),
                                               record_id=store.record_id_at("NLAM-OPS-LNX-04", "Linux-Sysmon/Operational", lt),
                                               host="NLAM-OPS-LNX-04", guid=_guid("med.nlam.tar"), pid=29110, ppid=28770,
                                               image="/usr/bin/tar", cmd=cmd, user="svc-transfer", parent_image="/bin/bash",
                                               cwd="/srv/transfer/incoming"),
        truth_label="malicious", technique="T1560.001", question_tags="archive,staging,multi_region",
    )
    for j, line in enumerate(linux.audit_exec(epoch=int(lt.timestamp()), serial=8400, host="NLAM-OPS-LNX-04",
                                              pid=29110, ppid=28770, uid=1007, exe="/usr/bin/tar", cmd=cmd)):
        store.add(
            key=f"med.nlam.tar.audit.{j}", activity_id="MED-STAGE-002", time=_iso(lt + timedelta(milliseconds=j)), host="NLAM-OPS-LNX-04",
            source="/var/log/audit/audit.log", sourcetype="linux_audit", raw=line,
            truth_label="malicious", technique="T1560.001", question_tags="archive,staging,multi_region",
        )

    # ------------------------------------------------------------------
    # 9. Exfil over HTTPS from NL.  The destination looks like ordinary cloud
    # storage; correlation to staging and account use is required.
    # ------------------------------------------------------------------
    t = ctx.at(3, 5, 31, 18)
    ex = ledger.add_flow(NetworkFlow(
        "MED-FLOW-EXFIL-001", t, nlam_stage, 51182, actor_exfil, 443,
        bytes_out=148337920, bytes_in=9144, duration=164.2, src_host="NLAM-OPS-LNX-04", dest_host=None,
        service="ssl", tags=("exfil", "https"),
    ))
    uid = _add_zeek_conn(store, t, "NLAM-ZEEK-01", ex, "med.exfil.conn", "MED-EXFIL-001", "T1048.002", "exfiltration,https,staged_archive", "ssl")
    store.add(
        key="med.exfil.tls", activity_id="MED-EXFIL-001", time=_iso(t + timedelta(milliseconds=14)), host="NLAM-ZEEK-01",
        source="zeek:ssl", sourcetype="zeek:ssl",
        raw=zeek.tls((t + timedelta(milliseconds=14)).timestamp(), uid, nlam_stage, 51182, actor_exfil, 443,
                     "objects-eu-west.examplecdn.net", "t13d1516h2_8daaf6152771_02713d6af862"),
        truth_label="malicious", technique="T1048.002", question_tags="exfiltration,https,staged_archive",
    )
    store.add(
        key="med.exfil.pan", activity_id="MED-EXFIL-001", time=_iso(t), host="NLAM-FW-02",
        source="pan:traffic", sourcetype="pan:traffic",
        raw=network_devices.palo_alto(t.strftime("%Y/%m/%d %H:%M:%S"), "PA-NLAM-002", nlam_stage, actor_exfil,
                                     51182, 443, "allow", "SERVER-WEB", "servers", "untrust",
                                     bytes_out=148337920, bytes_in=9144),
        truth_label="malicious", technique="T1048.002", question_tags="exfiltration,https,staged_archive",
    )
    store.add(
        key="med.exfil.dlp", activity_id="MED-EXFIL-001", time=_iso(t + timedelta(seconds=3)), host="NLAM-DLP-01",
        source="dlp:events", sourcetype="dlp:events",
        raw=apps.dlp(_iso(t + timedelta(seconds=3)), r"EU\\svc-transfer", "NLAM-OPS-LNX-04",
                     "sysdiag-20260409.tgz", 148337920, "objects-eu-west.examplecdn.net",
                     "Engineering Sensitive - External Upload", "medium", "allow_with_justification"),
        truth_label="malicious", technique="T1048.002", question_tags="exfiltration,dlp,weak_detection",
    )

    # Legitimate large transfer lookalike to an approved engineering partner.
    bt = ctx.at(3, 4, 52, 0)
    store.add(
        key="med.exfil.benign.mft", activity_id="MED-BENIGN-MFT-001", time=_iso(bt), host="DEFR-MFT-01",
        source="mft:transfer", sourcetype="mft:transfer",
        raw=apps.mft_transfer(_iso(bt), r"EU\\mroth", "DEFR-ENG-WS-114", "turbine-model-export.zip",
                              221403812, "partner-engineering.example", "upload", "success", "tx-med-benign-001"),
        truth_label="benign", question_tags="mft,large_transfer,benign_lookalike",
    )

    # ------------------------------------------------------------------
    # 10. Cleanup on DE and NL systems.
    # ------------------------------------------------------------------
    t = ctx.at(3, 6, 3, 42)
    _add_windows_process(store, t, "DEFR-ENG-APP-03", r"EU\\svc-engbuild",
                         r"C:\\Windows\\System32\\cmd.exe",
                         r'cmd.exe /c del /q "C:\\ProgramData\\Support\\eu-grid-review.7z" & rmdir /s /q "C:\\ProgramData\\Support\\review"',
                         r"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                         "med.cleanup.de", "MED-CLEANUP-001", "T1070.004", "cleanup,file_delete")
    lt = t + timedelta(minutes=7)
    cleanup_cmd = "/usr/bin/rm -f /var/tmp/.cache/sysdiag-20260409.tgz"
    store.add(
        key="med.cleanup.nl", activity_id="MED-CLEANUP-001", time=_iso(lt), host="NLAM-OPS-LNX-04",
        source="/var/log/syslog", sourcetype="syslog",
        raw=linux.linux_sysmon_process_generic(syslog_time=_syslog(lt), iso_time=_iso(lt),
                                               record_id=store.record_id_at("NLAM-OPS-LNX-04", "Linux-Sysmon/Operational", lt),
                                               host="NLAM-OPS-LNX-04", guid=_guid("med.cleanup.nl"), pid=29244, ppid=28770,
                                               image="/usr/bin/rm", cmd=cleanup_cmd, user="svc-transfer", parent_image="/bin/bash",
                                               cwd="/var/tmp/.cache"),
        truth_label="malicious", technique="T1070.004", question_tags="cleanup,file_delete",
    )

    return {
        "campaign": "medium",
        "actor_initial_ip": actor_london,
        "actor_exfil_ip": actor_exfil,
        "primary_regions": ["UKLO", "DEFR", "NLAM", "AUSY"],
        "network_flows": 4,
    }
