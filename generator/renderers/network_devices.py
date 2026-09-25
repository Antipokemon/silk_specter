from __future__ import annotations

import hashlib
import random


def _stable_numeric_id(*parts, digits=8):
    digest = hashlib.sha256('|'.join(map(str, parts)).encode()).hexdigest()
    low = 10 ** (digits - 1)
    span = 9 * low
    return low + (int(digest[:16], 16) % span)


def palo_alto(ts, serial, src, dst, sport, dport, action, rule, zone_from, zone_to,
              app='ssl', bytes_out=0, bytes_in=0, nat_dst='', nat_src='',
              src_user=r'asteron\netuser', dest_user='', vsys='vsys1',
              src_interface='ethernet1/1', dest_interface='ethernet1/2',
              log_forwarding_profile='forward-all', transport='tcp', duration=3,
              packets_out=None, packets_in=None, session_id=None, sequence_number=None,
              src_location='10.0.0.0-10.255.255.255', dest_location='United States'):
    """Render PAN-OS TRAFFIC CSV in Splunk_TA_paloalto_networks extract_traffic order."""
    total = int(bytes_out) + int(bytes_in)
    packets_out = packets_out if packets_out is not None else max(1, int(bytes_out) // 1200 + 1)
    packets_in = packets_in if packets_in is not None else max(1, int(bytes_in) // 1200 + 1)
    packets = packets_out + packets_in
    session_id = session_id or _stable_numeric_id(ts, serial, src, dst, sport, dport, digits=9)
    sequence_number = sequence_number or _stable_numeric_id('seq', ts, serial, src, dst, sport, dport, digits=10)
    src_translated = nat_src or src
    dest_translated = nat_dst or dst

    # This list is deliberately kept 1:1 with extract_traffic in
    # Splunk_TA_paloalto_networks/default/transforms.conf.
    fields = [
        '1',                    # future_use1
        ts,                     # receive_time
        serial,                 # serial_number
        'TRAFFIC',              # log_type
        'end',                  # log_subtype
        '10.2',                 # version
        ts,                     # generated_time
        src, dst,               # src_ip, dest_ip
        src_translated, dest_translated,
        rule, src_user, dest_user, app, vsys,
        zone_from, zone_to, src_interface, dest_interface, log_forwarding_profile,
        ts,                     # future_use3 (commonly time/session field in PAN exports)
        str(session_id), '1',   # session_id, repeat_count
        str(sport), str(dport), str(sport), str(dport),
        '0x400000', transport, action,
        str(total), str(bytes_out), str(bytes_in), str(packets),
        ts, str(duration), 'any', '',
        str(sequence_number), '0x0', src_location, dest_location, '',
        str(packets_out), str(packets_in), 'aged-out',
        '0', '0', '0', '0', vsys, serial,
        'from-policy', '', '',
        '0', '', '0', '', 'N/A',
    ]
    if len(fields) != 61:
        raise AssertionError(f'PAN traffic renderer produced {len(fields)} fields, expected 61')
    return ','.join(fields)


def fortigate(date,time,devname,src,dst,sport,dport,action,policy,srcintf,dstintf,service='HTTPS',sentbyte=0,rcvdbyte=0):
    return f'date={date} time={time} devname="{devname}" type="traffic" subtype="forward" level="notice" srcip={src} srcport={sport} srcintf="{srcintf}" dstip={dst} dstport={dport} dstintf="{dstintf}" proto=6 action="{action}" policyid={policy} service="{service}" sentbyte={sentbyte} rcvdbyte={rcvdbyte} duration=3'


def cisco_asa(ts, host, msgid, src, sport, dst, dport, action='Built outbound TCP connection', connection_id=None):
    connection_id = connection_id or _stable_numeric_id(ts, host, src, sport, dst, dport, digits=8)
    return f'{ts} {host} %ASA-6-{msgid}: {action} {connection_id} for outside:{dst}/{dport} ({dst}/{dport}) to inside:{src}/{sport} ({src}/{sport})'


def cisco_ios(ts,host,facility,message):
    return f'{ts} {host} %{facility}: {message}'


def cisco_ios_login(ts, host, user, src_ip, success=True, local_port=22):
    if success:
        return cisco_ios(ts, host, 'SEC_LOGIN-5-LOGIN_SUCCESS',
                         f'Login Success [user: {user}] [Source: {src_ip}] [localport: {local_port}] at {ts} UTC')
    return cisco_ios(ts, host, 'SEC_LOGIN-4-LOGIN_FAILED',
                     f'Login failed [user: {user}] [Source: {src_ip}] [localport: {local_port}] [Reason: Login Authentication Failed] at {ts} UTC')


def cisco_ios_config(ts, host, user, src_ip, method='vty0'):
    return cisco_ios(ts, host, 'SYS-5-CONFIG_I',
                     f'Configured from console by {user} on {method} ({src_ip})')


def junos_syslog(ts,host,process,message,pid=None):
    if pid is None:
        pid=_stable_numeric_id(ts,host,process,message,digits=5)
    return f'{ts} {host} {process}[{pid}]: {message}'


def junos_login(ts, host, user, src_ip, dest_ip, success=True, src_port=55222, dest_port=22, pid=None):
    pid = pid or _stable_numeric_id(ts, host, user, src_ip, digits=5)
    if success:
        return (f'{ts} {host} mgd[{pid}]: UI_LOGIN_EVENT '
                f'[junos@2636.1.1.1.2.164 username="{user}" class-name="super-user" local-peer="" pid="{pid}" '
                f'ssh-connection="{src_ip} {src_port} {dest_ip} {dest_port}" client-mode="cli"] '
                f"User '{user}' login, class 'super-user' [{pid}], ssh-connection '{src_ip} {src_port} {dest_ip} {dest_port}', client-mode 'cli'")
    return (f'{ts} {host} sshd[{pid}]: SSHD_LOGIN_FAILED '
            f'[junos@2636.1.1.1.2.164 username="{user}" source-address="{src_ip}" '
            f'destination-address="{dest_ip}" ssh-connection="{src_ip} {src_port} {dest_ip} {dest_port}" reason="authentication failed"] '
            f"Login failed for user '{user}' from host '{src_ip}' via ssh, connection '{src_ip} {src_port} {dest_ip} {dest_port}'")
