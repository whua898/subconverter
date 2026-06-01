import json, re, urllib.parse, os, sys, time, textwrap, html

def load_sub(path):
    with open(path, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

def summarize_nodes(data, n=10):
    nodes = []
    if isinstance(data, list):
        iter_list = data
    elif isinstance(data, dict):
        # 常见字段: proxies, proxiesExpanded, nodes
        for k in ('proxies','proxiesExpanded','nodes','nodeList','node_list'):
            if k in data and isinstance(data[k], list):
                iter_list = data[k]
                break
        else:
            iter_list = []
    else:
        iter_list = []
    for node in iter_list[:n]:
        brief = {}
        brief['remarks'] = node.get('remarks') or node.get('remark') or node.get('name') or 'N/A'
        brief['type'] = node.get('type') or node.get('proxy_type') or 'N/A'
        brief['server'] = node.get('server') or node.get('hostname') or node.get('host') or 'N/A'
        brief['port'] = node.get('port') or 'N/A'
        # Collect sample of keys for raw dump
        brief['keys'] = list(node.keys())[:20]
        nodes.append(brief)
    return nodes

def build_vmess_json(nodes):
    out = []
    for n in nodes:
        base = {
            'v': '2',
            'ps': n.get('remarks',''),
            'add': n.get('server',''),
            'port': str(n.get('port','')),
            'id': n.get('uuid',''),
            'aid': n.get('alterId', n.get('alter_id','0')),
            'net': n.get('network', n.get('net','tcp')),
            'type': 'none',
            'host': n.get('host',''),
            'path': n.get('path',''),
            'tls': n.get('tls','')
        }
        out.append(base)
    return out

def build_simples_json(nodes, proto='vless', defaults_port=443):
    out = []
    for n in nodes:
        item = {
            'type': proto,
            'server': n.get('server',''),
            'port': str(n.get('port', defaults_port)),
            'uuid': n.get('uuid',''),
            'udp': True,
            'skip-cert-verify': True
        }
        # optional
        for k in ('tls','servername','flow','network','reality-opts'):
            if k in n and n[k]:
                item[k] = n[k]
        out.append(item)
    return out

def encode_json_to_b64(obj):
    import base64
    s = json.dumps(obj, ensure_ascii=False)
    b = s.encode('utf-8')
    return base64.b64encode(b).decode('utf-8')

def main():
    path = 'sub.txt'
    if not os.path.exists(path):
        print('missing ', path); sys.exit(1)
    data = load_sub(path)
    sample = summarize_nodes(data, n=5)
    print('TOTAL_TYPE sample:')
    for i, s in enumerate(sample,1):
        print(i, s)
    # Build vless vmess trojan ss compact JSON sets
    vms = build_vmess_json(sample)
    vless = build_simples_json(sample, 'vless')
    trojan = build_simples_json(sample, 'trojan')
    ss = build_simples_json(sample, 'ss')
    print('\n--- vless base64 head ---')
    print(encode_json_to_b64(vless)[:200])
    print('\n--- trojan base64 head ---')
    print(encode_json_to_b64(trojan)[:200])
    print('\n--- ss base64 head ---')
    print(encode_json_to_b64(ss)[:200])

if __name__ == '__main__':
    main()