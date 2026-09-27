from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import time
import copy
import ssl
import dns
import json

import requests

from typing import Optional, Tuple, Any, Dict, List, Union

import dns.message
import dns.flags
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.edns
import dns.name
import dns.rrset
import struct
import ipaddress
import binascii


# ============================================================
# 函数1：DNS 报文 → 字典
# ============================================================
def message_to_dict(msg_or_wire: Union[dns.message.Message, bytes, bytearray]) -> Dict[str, Any]:
    if isinstance(msg_or_wire, (bytes, bytearray)):
        try:
            msg = dns.message.from_wire(bytes(msg_or_wire))
        except Exception as e:
            raise ValueError(f"无法解析 DNS 报文: {e}")
    elif isinstance(msg_or_wire, dns.message.Message):
        msg = msg_or_wire
    else:
        raise TypeError("输入必须是 dns.message.Message 或 bytes/bytearray 类型")

    # Header
    flags_list = []
    if msg.flags & dns.flags.QR: flags_list.append('QR')
    if msg.flags & dns.flags.AA: flags_list.append('AA')
    if msg.flags & dns.flags.TC: flags_list.append('TC')
    if msg.flags & dns.flags.RD: flags_list.append('RD')
    if msg.flags & dns.flags.RA: flags_list.append('RA')
    if msg.flags & dns.flags.AD: flags_list.append('AD')
    if msg.flags & dns.flags.CD: flags_list.append('CD')

    header = {
        'id': msg.id,
        'flags': flags_list,
        'opcode': dns.opcode.to_text(msg.opcode()),
        'rcode': dns.rcode.to_text(msg.rcode()),
        'qdcount': len(msg.question),
        'ancount': len(msg.answer),
        'nscount': len(msg.authority),
        'arcount': len(msg.additional),
    }

    # Question
    question = []
    for q in msg.question:
        question.append({
            'name': q.name.to_text(),
            'type': dns.rdatatype.to_text(q.rdtype),
            'class': dns.rdataclass.to_text(q.rdclass),
        })

    # 【修正 5】不再截断 rdata 文本，直接用 rdata.to_text()
    def section_to_list(section):
        records = []
        for rrset in section:
            name = rrset.name.to_text()
            rtype = dns.rdatatype.to_text(rrset.rdtype)
            rclass = dns.rdataclass.to_text(rrset.rdclass)
            ttl = rrset.ttl
            for rdata in rrset:
                records.append({
                    'name': name,
                    'type': rtype,
                    'class': rclass,
                    'ttl': ttl,
                    'data': rdata.to_text(),
                })
        return records

    answer = section_to_list(msg.answer)
    authority = section_to_list(msg.authority)

    # Additional（分离 OPT）
    additional = []
    edns_dict = None

    for rrset in msg.additional:
        if rrset.rdtype == dns.rdatatype.OPT:
            for opt_rr in rrset:
                # 【修正 6】修正 EDNS 字段位移
                edns_dict = {
                    'version':        (opt_rr.ednsflags >> 16) & 0xFF,
                    'udp_payload':    opt_rr.udp_payload,
                    'extended_rcode': (opt_rr.ednsflags >> 24) & 0xFF,
                    'flags':          opt_rr.ednsflags & 0xFFFF,
                    'options':        [],
                }
                for opt in opt_rr.options:
                    edns_dict['options'].append(_decode_edns_option(opt))
        else:
            name = rrset.name.to_text()
            rtype = dns.rdatatype.to_text(rrset.rdtype)
            rclass = dns.rdataclass.to_text(rrset.rdclass)
            ttl = rrset.ttl
            for rdata in rrset:
                additional.append({
                    'name': name,
                    'type': rtype,
                    'class': rclass,
                    'ttl': ttl,
                    'data': rdata.to_text(),
                })

    result = {
        'header': header,
        'question': question,
        'answer': answer,
        'authority': authority,
        'additional': additional,
    }
    if edns_dict:
        result['edns'] = edns_dict
    return result


def _decode_edns_option(opt) -> Dict[str, Any]:
    # 【修正 1】使用 OptionType.to_text
    try:
        name = dns.edns.OptionType.to_text(opt.otype)
    except Exception:
        name = str(opt.otype)

    entry = {
        'code': opt.otype,
        'name': name,
        'data_hex': opt.data.hex() if isinstance(opt.data, bytes) else None,
    }

    # 【修正 7】数据非 bytes 时直接返回
    if not isinstance(opt.data, bytes):
        return entry

    if opt.otype == 8:          # ECS
        try:
            family = struct.unpack('!H', opt.data[0:2])[0]
            src_prefix = opt.data[2]
            scope_prefix = opt.data[3]
            addr_bytes = opt.data[4:]
            # 【修正 8】地址字节补齐
            if family == 1:
                addr = str(ipaddress.IPv4Address(addr_bytes.ljust(4, b'\x00')[:4]))
            elif family == 2:
                addr = str(ipaddress.IPv6Address(addr_bytes.ljust(16, b'\x00')[:16]))
            else:
                addr = binascii.hexlify(addr_bytes).decode()
            entry.update({
                'ecs_family': family,
                'ecs_source_prefix': src_prefix,
                'ecs_scope_prefix': scope_prefix,
                'ecs_address': addr,
            })
        except Exception:
            pass
    elif opt.otype == 3:        # NSID
        entry['nsid'] = opt.data.decode('ascii', errors='replace')
    elif opt.otype == 10:       # COOKIE
        if len(opt.data) == 8:
            entry['client_cookie'] = opt.data.hex()
        elif len(opt.data) > 8:
            entry['client_cookie'] = opt.data[:8].hex()
            entry['server_cookie'] = opt.data[8:].hex()
    elif opt.otype == 5:        # DAU
        entry['algorithms'] = list(opt.data)
    elif opt.otype == 6:        # DHU
        entry['hash_algorithms'] = list(opt.data)

    return entry


# ============================================================
# 函数2：字典 → DNS 报文（返回 Message 对象）
# ============================================================
def dict_to_message(data: Dict[str, Any]) -> dns.message.Message:
    msg = dns.message.Message()

    hdr = data.get('header', {})
    msg.id = hdr.get('id', 0)

    flag_map = {
        'QR': dns.flags.QR, 'AA': dns.flags.AA, 'TC': dns.flags.TC,
        'RD': dns.flags.RD, 'RA': dns.flags.RA, 'AD': dns.flags.AD,
        'CD': dns.flags.CD,
    }
    flags_val = 0
    for flag_str in hdr.get('flags', []):
        if flag_str in flag_map:
            flags_val |= flag_map[flag_str]
    msg.flags = flags_val

    if 'opcode' in hdr:
        try:
            msg.set_opcode(dns.opcode.from_text(hdr['opcode']))
        except Exception:
            pass
    if 'rcode' in hdr:
        try:
            msg.set_rcode(dns.rcode.from_text(hdr['rcode']))
        except Exception:
            pass

    # Question
    for q in data.get('question', []):
        try:
            qname = dns.name.from_text(q['name'])
            qtype = dns.rdatatype.from_text(q['type'])
            qclass = dns.rdataclass.from_text(q.get('class', 'IN'))
            msg.question.append(dns.rrset.RRset(qname, qclass, qtype))
        except Exception as e:
            raise ValueError(f"无效的 Question 记录: {q}, 错误: {e}")

    def add_rrsets_to_section(section, rec_list):
        groups = {}
        for rec in rec_list:
            key = (rec['name'], rec['type'], rec.get('class', 'IN'))
            groups.setdefault(key, []).append(rec)

        for (name_str, type_str, class_str), recs in groups.items():
            # 【修正 12】初始化 data_str 避免未绑定错误
            data_str = ''
            try:
                name = dns.name.from_text(name_str)
                rdtype = dns.rdatatype.from_text(type_str)
                rdclass = dns.rdataclass.from_text(class_str)
                rrset = dns.rrset.RRset(name, rdclass, rdtype)

                for rec in recs:
                    ttl = rec.get('ttl', 300)
                    data_str = rec.get('data') or rec.get('rdata', '')

                    if rdtype == dns.rdatatype.SOA:
                        data_str = _normalize_soa_rdata(data_str)
                    elif rdtype in (dns.rdatatype.HTTPS, dns.rdatatype.SVCB):
                        data_str = _normalize_svcb_rdata(data_str)

                    rdata = dns.rdata.from_text(rdclass, rdtype, data_str)
                    rrset.add(rdata, ttl=ttl)
                section.append(rrset)
            except Exception as e:
                raise ValueError(
                    f"无法构建 RRset (name={name_str}, type={type_str}): {e}\n"
                    f"数据字符串: '{data_str}'"
                )

    add_rrsets_to_section(msg.answer,     data.get('answer', []))
    add_rrsets_to_section(msg.authority,  data.get('authority', []))
    add_rrsets_to_section(msg.additional, data.get('additional', []))

    # EDNS
    if 'edns' in data and data['edns']:
        edns_info = data['edns']
        version        = int(edns_info.get('version', 0))
        udp_payload    = int(edns_info.get('udp_payload', 1232))
        # 【修正 6】flags 是 16 位，直接传；extended_rcode 单独传
        edns_flags     = int(edns_info.get('flags', 0)) & 0xFFFF
        extended_rcode = int(edns_info.get('extended_rcode', 0)) & 0xFF

        options = []
        for opt_entry in edns_info.get('options', []):
            if opt_entry.get('data_hex'):
                raw_data = bytes.fromhex(opt_entry['data_hex'])
            else:
                raw_data = _encode_edns_option_from_decoded(opt_entry)
            # 【修正 3】使用 GenericOption
            options.append(dns.edns.GenericOption(opt_entry['code'], raw_data))

        # 【修正 2】正确参数名
        msg.use_edns(
            edns=version,
            ednsflags=edns_flags,
            payload=udp_payload,
            extended_rcode=extended_rcode,
            options=options,
        )

    # 【修正 4】返回 Message 对象，符合类型声明
    return msg


def _normalize_soa_rdata(data_str: str) -> str:
    parts = data_str.split()
    if len(parts) != 7:
        return data_str
    mname, rname, serial, refresh, retry, expire, minimum = parts
    if not mname.endswith('.'):
        mname += '.'
    if not rname.endswith('.'):
        rname += '.'
    for field in (serial, refresh, retry, expire, minimum):
        try:
            int(field)
        except ValueError:
            return data_str
    return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"


def _normalize_svcb_rdata(data_str: str) -> str:
    data_str = (data_str or '').strip()
    if not data_str:
        return "1 ."
    parts = data_str.split(maxsplit=2)
    try:
        int(parts[0])
        if len(parts) >= 2:
            return data_str
        return f"{parts[0]} ."
    except ValueError:
        if data_str.startswith('.'):
            rest = data_str[1:].lstrip()
            return f"1 . {rest}" if rest else "1 ."
        return f"1 . {data_str}"


def _encode_edns_option_from_decoded(opt_entry: Dict[str, Any]) -> bytes:
    code = opt_entry.get('code')
    if code == 8:   # ECS
        family = opt_entry.get('ecs_family', 1)
        src_prefix = opt_entry.get('ecs_source_prefix', 0)
        scope_prefix = opt_entry.get('ecs_scope_prefix', 0)
        addr_str = opt_entry.get('ecs_address', '0.0.0.0')
        addr = ipaddress.ip_address(addr_str)
        return struct.pack('!HBB', family, src_prefix, scope_prefix) + addr.packed
    elif code == 3:
        return opt_entry.get('nsid', '').encode('ascii', errors='replace')
    elif code == 10:
        client = opt_entry.get('client_cookie', '')
        server = opt_entry.get('server_cookie', '')
        out = b''
        if client:
            out += bytes.fromhex(client)
        if server:
            out += bytes.fromhex(server)
        return out
    elif code == 5:
        return bytes(opt_entry.get('algorithms', []))
    elif code == 6:
        return bytes(opt_entry.get('hash_algorithms', []))
    return b''


def dict_to_wire(data: Dict[str, Any]) -> bytes:
    return dict_to_message(data).to_wire()


def d2r(data: Dict[str, Any]) -> bytes:
    """保持与原来 d2r = dict_to_message 相同的“返回 bytes”行为。"""
    return dict_to_message(data).to_wire()


# 保留别名语义：r2d 与 message_to_dict 行为一致
r2d = message_to_dict


# ============================================================
# 以下保持原有逻辑，仅修正若干小问题
# ============================================================
def send2upsteram(query_data, UPSTREAM):
    upstream_resp = requests.post(
        UPSTREAM,
        data=query_data,
        headers={'Content-Type': 'application/dns-message'},
        timeout=5,
    )
    return upstream_resp


def build_query(n, t):
    query_dict = {
        'header': {'id': 0, 'flags': ['RD'], 'opcode': 'QUERY',
                   'rcode': 'NOERROR', 'qdcount': 1, 'ancount': 0,
                   'nscount': 0, 'arcount': 0},
        'question': [{'name': '', 'type': '', 'class': 'IN'}],
        'answer': [], 'authority': [], 'additional': [],
    }
    query_dict['question'][0]['name'] = n
    query_dict['question'][0]['type'] = t
    return query_dict


def name_handler(dns_result, name_dict, cdn_dict):
    dns_dict = r2d(dns_result)

    # 【修正 10】按最长后缀优先匹配
    def name_chooser(d, n):
        return sorted((i for i in n.keys() if d.endswith(i)),
                      key=len, reverse=True)

    matched_list = name_chooser(dns_dict['question'][0]['name'], name_dict)
    print(matched_list)
    print(dns_dict)

    if not matched_list:
        return dns_result
    sub_dict = name_dict[matched_list[0]]
    print(sub_dict)

    if dns_dict['question'][0]['type'] not in ['HTTPS', 'A', 'AAAA']:
        return dns_result

    # 检查是否已存在含 ECH 的回答
    if dns_dict['question'][0]['type'] == 'HTTPS':
        for ans in dns_dict.get('answer', []):
            if 'ech=' in ans.get('data', ''):
                return dns_result

    if sub_dict['ech_only'] == 1:
        if dns_dict['question'][0]['type'] != 'HTTPS':
            return dns_result

        def add_ech(dns_result, ech_pubkey, ttl):
            answer = copy.deepcopy(dns_result['question'][0])
            answer['data'] = '1 . ' + ech_pubkey
            answer['ttl'] = ttl
            dns_result['answer'] = [answer]
            dns_result['header']['ancount'] = 1
            dns_result['header']['nscount'] = 0
            dns_result['authority'] = []
            return dns_result

        n = cdn_dict[sub_dict['cdn']]
        t = dns_dict['question'][0]['type']
        query = build_query(n, t)

        try:
            print('ech query')
            dns_response = send2upsteram(d2r(query), UPSTREAM)
            print('ech query success')
        except requests.RequestException as e:
            print(f"Upstream error: {e}")
            return dns_result

        ech_res_dict = r2d(dns_response.content)
        # 【修正 14】防越界
        if not ech_res_dict.get('answer'):
            return dns_result

        candidates = [i for i in ech_res_dict['answer'][0]['data'].split(' ')
                      if i.startswith('ech=')]
        if not candidates:
            return dns_result

        ech_pubkey = candidates[0]
        ttl = ech_res_dict['answer'][0]['ttl']
        modified_dns = add_ech(dns_dict, ech_pubkey, ttl)
        return d2r(modified_dns)

    if sub_dict['ech_only'] == 0:
        def answer_replace(old_data, fake_answer):
            answer = []
            for i in fake_answer:
                if i['type'] not in ['A', 'AAAA', 'HTTPS']:
                    answer.append(i)
                else:
                    i['name'] = old_data['question'][0]['name']
                    answer.append(i)
            old_data['answer'] = answer
            # 【修正 9】ancount 与实际条目数一致
            old_data['header']['ancount'] = len(answer)
            old_data['header']['nscount'] = 0
            old_data['authority'] = []
            return old_data

        n = cdn_dict[sub_dict['cdn']]
        t = dns_dict['question'][0]['type']
        query = build_query(n, t)
        print(query)

        try:
            print(t + ' query')
            dns_response = send2upsteram(d2r(query), UPSTREAM)
        except requests.RequestException as e:
            print(f"Upstream error: {e}")
            return dns_result

        res_dict = r2d(dns_response.content)
        print(res_dict)
        modified_dns = answer_replace(dns_dict, res_dict['answer'])
        print(modified_dns)
        return d2r(modified_dns)

    return dns_result


class MyHandler(BaseHTTPRequestHandler):

    def __send_json(self, dic, state=200):
        self.send_response(state)
        self.send_header('Content-Type', 'application/dns-message')
        self.end_headers()
        self.wfile.write((json.dumps(dic) + '\n').encode('utf-8'))

    def do_GET(self):
        path_l = self.path.split('/')
        path_l = [i for i in path_l if i != '']
        print(path_l)
        # 【修正 11】正确返回 200
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'ok')

    def do_POST(self):
        if 'query' not in self.path:
            self.send_error(400, 'Bad Request')
            return
        if self.headers.get('Content-Type') != 'application/dns-message':
            self.send_error(415, 'Unsupported Media Type')
            return
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length == 0:
            self.send_error(400, 'Bad Request')
            return

        query_data = self.rfile.read(content_length)
        print('Sen')
        print(r2d(query_data))

        try:
            upstream_resp = send2upsteram(query_data, UPSTREAM)
        except requests.RequestException as e:
            print(f"Upstream error: {e}")
            self.send_error(502, 'Bad Gateway')
            return

        # 【修正 13】非 200 直接返回错误
        if upstream_resp.status_code != 200:
            self.send_error(502, 'Bad Gateway')
            return

        self.send_response(200)
        self.send_header('Content-Type', 'application/dns-message')
        self.end_headers()

        print('Res')
        qd = name_handler(upstream_resp.content, name_dict, cdn_dict)
        self.wfile.write(qd)


# ============================================================
# 全局配置
# ============================================================
UPSTREAM = 'https://wikimedia-dns.org/dns-query'

# 【修正 15】示例配置，按需替换




ech_only=lambda c :{'cdn':c,'ech_only':1}
all_proxy=lambda c :{'cdn':c,'ech_only':0}
eo=ech_only
ap=all_proxy

name_dict={'cdn.onesignal.com.':eo('cloudflare'),'ads-pixiv.net.':eo('google'),'pixiv.net.':eo('cloudflare'),'pximg.net.':ap('cloudflare'),'fanbox.cc.':ap('cloudflare'),'booth.pm.':ap('cloudflare'),'wikimedia.org.':eo('wikimedia'),'wikipedia.org.':eo('wikimedia')}

cdn_dict={'google':'google.com.','cloudflare':'encryptedsni.com.','wikimedia':'wikimedia.org.'}


if __name__ == '__main__':
    server_address = ('', 8443)
    httpd = HTTPServer(server_address, MyHandler)
#    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
#    context.load_cert_chain(certfile='fullchain.pem', keyfile='privkey.pem')
#   httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print('Starting server...')
    httpd.serve_forever()
