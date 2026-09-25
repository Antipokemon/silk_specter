import json
import hashlib

def conn(ts, uid, orig_h, orig_p, resp_h, resp_p, *, proto='tcp', service='-', duration=0.2, orig_bytes=120, resp_bytes=340, conn_state='SF', local_orig=True, local_resp=False):
    return json.dumps({'ts':ts,'uid':uid,'id.orig_h':orig_h,'id.orig_p':orig_p,'id.resp_h':resp_h,'id.resp_p':resp_p,'proto':proto,'service':service,'duration':duration,
        'orig_bytes':orig_bytes,'resp_bytes':resp_bytes,'conn_state':conn_state,'local_orig':local_orig,'local_resp':local_resp,'missed_bytes':0,'history':'ShADadFf','orig_pkts':8,'orig_ip_bytes':orig_bytes+320,'resp_pkts':7,'resp_ip_bytes':resp_bytes+280},separators=(',',':'))

def dns(ts, uid, orig_h, orig_p, resp_h, query, answers, qtype_name='A'):
    return json.dumps({'ts':ts,'uid':uid,'id.orig_h':orig_h,'id.orig_p':orig_p,'id.resp_h':resp_h,'id.resp_p':53,'proto':'udp','trans_id':24211,'rtt':0.0021,'query':query,'qclass':1,'qclass_name':'C_INTERNET','qtype':1,'qtype_name':qtype_name,'rcode':0,'rcode_name':'NOERROR','AA':False,'TC':False,'RD':True,'RA':True,'Z':0,'answers':answers,'TTLs':[60.0],'rejected':False},separators=(',',':'))

def http(ts, uid, orig_h, orig_p, resp_h, resp_p, method, host, uri, status, user_agent, resp_len=512):
    return json.dumps({'ts':ts,'uid':uid,'id.orig_h':orig_h,'id.orig_p':orig_p,'id.resp_h':resp_h,'id.resp_p':resp_p,'trans_depth':1,'method':method,'host':host,'uri':uri,'referrer':'-','version':'1.1','user_agent':user_agent,'request_body_len':0,'response_body_len':resp_len,'status_code':status,'status_msg':'OK' if status<400 else 'Error','tags':[],'resp_fuids':[],'resp_mime_types':['text/html']},separators=(',',':'))

def tls(ts, uid, orig_h, orig_p, resp_h, resp_p, server_name, ja4, cert_chain='Fcert01'):
    return json.dumps({'ts':ts,'uid':uid,'id.orig_h':orig_h,'id.orig_p':orig_p,'id.resp_h':resp_h,'id.resp_p':resp_p,'version':'TLSv13','cipher':'TLS_AES_256_GCM_SHA384','curve':'x25519','server_name':server_name,'resumed':False,'last_alert':0,'next_protocol':'h2','established':True,'cert_chain_fuids':[cert_chain],'client_cert_chain_fuids':[],'ja4':ja4},separators=(',',':'))

def smb(ts, uid, orig_h, resp_h, path, name, action='SMB2_READ'):
    return json.dumps({'ts':ts,'uid':uid,'id.orig_h':orig_h,'id.orig_p':52144,'id.resp_h':resp_h,'id.resp_p':445,'action':action,'path':path,'name':name},separators=(',',':'))

def dce_rpc(ts, uid, orig_h, resp_h, endpoint='IWbemLevel1Login', operation='NTLMLogin'):
    return json.dumps({'ts':ts,'uid':uid,'id.orig_h':orig_h,'id.orig_p':52145,'id.resp_h':resp_h,'id.resp_p':135,'rtt':0.021,'named_pipe':'\\\\PIPE\\epmapper','endpoint':endpoint,'operation':operation},separators=(',',':'))


def files(ts, fuid, uid, tx_hosts, rx_hosts, source, mime_type, filename, total_bytes, sha256=''):
    return json.dumps({'ts':ts,'fuid':fuid,'tx_hosts':tx_hosts,'rx_hosts':rx_hosts,'conn_uids':[uid],'source':source,'depth':0,'analyzers':['SHA256'],'mime_type':mime_type,'filename':filename,'duration':0.0,'local_orig':True,'is_orig':True,'seen_bytes':total_bytes,'total_bytes':total_bytes,'missing_bytes':0,'overflow_bytes':0,'timedout':False,'sha256':sha256},separators=(',',':'))


def x509(ts, fingerprint, certificate_version, serial, subject, issuer, not_valid_before, not_valid_after, key_alg='rsaEncryption', key_length=2048, san_dns=None):
    fp=str(fingerprint).replace(':','').strip()
    if len(fp) not in (40,64) or any(c not in '0123456789abcdefABCDEF' for c in fp):
        fp=hashlib.sha256(f'{serial}|{subject}|{issuer}|{fingerprint}'.encode()).hexdigest().upper()
    else:
        fp=fp.upper()
    return json.dumps({'ts':ts,'fingerprint':fp,'certificate.version':certificate_version,'certificate.serial':serial,'certificate.subject':subject,'certificate.issuer':issuer,'certificate.not_valid_before':not_valid_before,'certificate.not_valid_after':not_valid_after,'certificate.key_alg':key_alg,'certificate.sig_alg':'sha256WithRSAEncryption','certificate.key_type':'rsa','certificate.key_length':key_length,'san.dns':san_dns or []},separators=(',',':'))
