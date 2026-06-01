import requests
import base64
import json
import sys

tgt = 'https://whua-bp.8dy.xx.kg/sub/normal/wh898?app=xray#%F0%9F%92%A6%20BPB%20Normal'

r = requests.get(tgt, timeout=20)
status = r.status_code
txt = r.text.strip()
clen = len(txt)
err = ''
tb64 = 0
decoded = ''
is_b64 = False

try:
    raw = base64.b64decode(txt)
    decoded = raw.decode('utf-8', 'ignore')
    tb64 = 1
except Exception:
    try:
        pad = '=' * (-len(txt) % 4)
        raw = base64.urlsafe_b64decode(txt + pad)
        decoded = raw.decode('utf-8', 'ignore')
        tb64 = 2
    except Exception as e:
        err = 'base64_decode_failed'
        is_b64 = False

if tb64 and not err:
    if 'vmess://' in decoded or 'ss://' in decoded:
        is_b64 = True
    elif any(decoded.startswith(p) for p in ('trojan://', 'vless://', 'hysteria2://', 'tuic://', 'ssr://')):
        is_b64 = True
    else:
        err = 'no_known_proto'
        is_b64 = True

nodes = 0
protos = []

if is_b64:
    lines = [x.strip() for x in decoded.splitlines() if x.strip()]
    nodes = len(lines)
    for it in lines[:20]:
        low = it.lower()
        if low.startswith('vmess://') or low.startswith('vmess:'):
            protos.append('vmess')
            break
        if low.startswith('vless://') or low.startswith('vless:'):
            protos.append('vless')
            break
        if low.startswith('ss://') or low.startswith('ss:'):
            protos.append('ss')
            break
        if low.startswith('trojan://') or low.startswith('trojan:'):
            protos.append('trojan')
            break
        if low.startswith('hysteria2://') or low.startswith('hysteria2:') or 'hysteria2' in low:
            protos.append('hysteria2')
            break
        if low.startswith('tuic://') or low.startswith('tuic:'):
            protos.append('tuic')
            break
        if low.startswith('ssr://') or low.startswith('ssr:'):
            protos.append('ssr')
            break

print(json.dumps({
    'status_code': status,
    'content_length': clen,
    'valid_base64': bool(is_b64),
    'error': err,
    'protocols': protos,
    'nodes': nodes,
    'preview': decoded[:120] if decoded else txt[:120]
}, ensure_ascii=False))