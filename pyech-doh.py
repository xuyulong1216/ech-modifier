from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
#import multiprocessing
import time
import copy
import ssl
import dns
#import data_read
import json

import requests

from typing import Optional, Tuple


import dns.message
import dns.flags
import dns.opcode
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rdata
import dns.edns
import dns.name
import struct
import ipaddress
import binascii
# ============================================================
# 函数1：DNS 报文 → 字典
# ============================================================
def message_to_dict(msg_or_wire: Union[dns.message.Message, bytes, bytearray]) -> Dict[str, Any]:
    if isinstance(msg_or_wire, (bytes, bytearray)):
        try:
            msg = dns.message.from_wire(msg_or_wire)
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
        'arcount': len(msg.additional)
    }

    # Question
    question = []
    for q in msg.question:
        question.append({
            'name': q.name.to_text(),
            'type': dns.rdatatype.to_text(q.rdtype),
            'class': dns.rdataclass.to_text(q.rdclass)
        })

    def section_to_list(section):
        records = []
        for rrset in section:
            name = rrset.name.to_text()
            rtype = dns.rdatatype.to_text(rrset.rdtype)
            rclass = dns.rdataclass.to_text(rrset.rdclass)
            ttl = rrset.ttl
            for rdata in rrset:
                full_text = rdata.to_text()
                # 对 HTTPS/SVCB 保留完整文本，不进行截断
                if rrset.rdtype in (dns.rdatatype.HTTPS, dns.rdatatype.SVCB):
                    data_text = full_text
                else:
                    parts = full_text.split(maxsplit=1)
                    data_text = parts[1] if len(parts) > 1 else full_text
                records.append({
                    'name': name,
                    'type': rtype,
                    'class': rclass,
                    'ttl': ttl,
                    'data': data_text
                })
        return records

    answer = section_to_list(msg.answer)
    authority = section_to_list(msg.authority)

    # Additional (分离 OPT)
    additional = []
    edns_dict = None

    for rrset in msg.additional:
        if rrset.rdtype == dns.rdatatype.OPT:
            for opt_rr in rrset:
                edns_dict = {
                    'version': (opt_rr.ednsflags >> 16) & 0xFF,
                    'udp_payload': opt_rr.udp_payload,
                    'extended_rcode': opt_rr.ednsflags & 0xFF,
                    'flags': opt_rr.ednsflags & 0xFFFF0000,
                    'options': []
                }
                for opt in opt_rr.options:
                    opt_entry = _decode_edns_option(opt)
                    edns_dict['options'].append(opt_entry)
        else:
            name = rrset.name.to_text()
            rtype = dns.rdatatype.to_text(rrset.rdtype)
            rclass = dns.rdataclass.to_text(rrset.rdclass)
            ttl = rrset.ttl
            for rdata in rrset:
                full_text = rdata.to_text()
                if rrset.rdtype in (dns.rdatatype.HTTPS, dns.rdatatype.SVCB):
                    data_text = full_text
                else:
                    parts = full_text.split(maxsplit=1)
                    data_text = parts[1] if len(parts) > 1 else full_text
                additional.append({
                    'name': name,
                    'type': rtype,
                    'class': rclass,
                    'ttl': ttl,
                    'data': data_text
                })

    result = {
        'header': header,
        'question': question,
        'answer': answer,
        'authority': authority,
        'additional': additional
    }
    if edns_dict:
        result['edns'] = edns_dict
    return result


def _decode_edns_option(opt: dns.edns.Option) -> Dict[str, Any]:
    entry = {
        'code': opt.otype,
        'name': dns.edns.option_type_to_text(opt.otype),
        'data_hex': opt.data.hex() if isinstance(opt.data, bytes) else None
    }

    if opt.otype == 8:          # ECS
        try:
            family = struct.unpack('!H', opt.data[0:2])[0]
            src_prefix = opt.data[2]
            scope_prefix = opt.data[3]
            addr_bytes = opt.data[4:]
            if family == 1:
                addr = str(ipaddress.IPv4Address(addr_bytes[:4]))
            elif family == 2:
                addr = str(ipaddress.IPv6Address(addr_bytes[:16]))
            else:
                addr = binascii.hexlify(addr_bytes).decode()
            entry.update({
                'ecs_family': family,
                'ecs_source_prefix': src_prefix,
                'ecs_scope_prefix': scope_prefix,
                'ecs_address': addr
            })
        except Exception:
            pass
    elif opt.otype == 3:        # NSID
        try:
            entry['nsid'] = opt.data.decode('ascii', errors='replace')
        except Exception:
            pass
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
# 函数2：字典 → DNS 报文
# ============================================================
def dict_to_message(data: Dict[str, Any]) -> dns.message.Message:
    msg = dns.message.Message()

    # Header
    hdr = data.get('header', {})
    msg.id = hdr.get('id', 0)

    flags_val = 0
    flag_map = {
        'QR': dns.flags.QR, 'AA': dns.flags.AA, 'TC': dns.flags.TC,
        'RD': dns.flags.RD, 'RA': dns.flags.RA, 'AD': dns.flags.AD, 'CD': dns.flags.CD
    }
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

    def add_rrsets_to_section(section: List, rec_list: List[Dict]) -> None:
        groups = {}
        for rec in rec_list:
            key = (rec['name'], rec['type'], rec.get('class', 'IN'))
            if key not in groups:
                groups[key] = []
            groups[key].append(rec)

        for (name_str, type_str, class_str), recs in groups.items():
            try:
                name = dns.name.from_text(name_str)
                rdtype = dns.rdatatype.from_text(type_str)
                rdclass = dns.rdataclass.from_text(class_str)
                rrset = dns.rrset.RRset(name, rdclass, rdtype)

                for rec in recs:
                    ttl = rec.get('ttl', 300)
                    data_str = rec.get('data') or rec.get('rdata', '')

                    # 规范化特殊记录类型
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

    add_rrsets_to_section(msg.answer, data.get('answer', []))
    add_rrsets_to_section(msg.authority, data.get('authority', []))
    add_rrsets_to_section(msg.additional, data.get('additional', []))

    # EDNS
    if 'edns' in data:
        edns_info = data['edns']
        version = edns_info.get('version', 0)
        udp_payload = edns_info.get('udp_payload', 1232)
        edns_flags = edns_info.get('flags', 0)
        extended_rcode = edns_info.get('extended_rcode', 0)

        options = []
        for opt_entry in edns_info.get('options', []):
            if 'data_hex' in opt_entry and opt_entry['data_hex']:
                raw_data = bytes.fromhex(opt_entry['data_hex'])
            else:
                raw_data = _encode_edns_option_from_decoded(opt_entry)
            options.append(dns.edns.Option(opt_entry['code'], raw_data))

        msg.use_edns(
            edns_version=version,
            udp_payload=udp_payload,
            edns_flags=edns_flags,
            extended_rcode=extended_rcode,
            options=options
        )

    return msg.to_wire()


def _normalize_soa_rdata(data_str: str) -> str:
    parts = data_str.split()
    if len(parts) != 7:
        return data_str
    mname, rname, serial, refresh, retry, expire, minimum = parts
    if not mname.endswith('.'):
        mname += '.'
    if not rname.endswith('.'):
        rname += '.'
    if '@' in rname:
        rname = rname.replace('@', '.')
    for field in [serial, refresh, retry, expire, minimum]:
        try:
            int(field)
        except ValueError:
            return data_str
    return f"{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"


def _normalize_svcb_rdata(data_str: str) -> str:
    """
    确保 HTTPS/SVCB 记录的 rdata 字符串包含优先级和目标名。
    格式应为：priority target_name [parameters...]
    若缺失则补全默认值：priority=1, target='.'
    """
    # 移除首尾空白
    data_str = data_str.strip()
    if not data_str:
        return "1 ."

    # 检查是否以数字开头（优先级）
    parts = data_str.split(maxsplit=2)
    try:
        int(parts[0])
        # 第一个部分是数字，格式可能已经正确
        if len(parts) >= 2:
            return data_str
        else:
            # 只有优先级，补上目标
            return f"{parts[0]} ."
    except ValueError:
        # 第一个部分不是整数，可能是缺失优先级，或者以点开头
        if data_str.startswith('.'):
            # 形如 ". alpn=..."
            remaining = data_str[1:].lstrip()
            return f"1 . {remaining}" if remaining else "1 ."
        else:
            # 可能直接是参数部分，如 "alpn=..."
            return f"1 . {data_str}"


def _encode_edns_option_from_decoded(opt_entry: Dict[str, Any]) -> bytes:
    code = opt_entry.get('code')
    if code == 8:   # ECS
        family = opt_entry.get('ecs_family', 1)
        src_prefix = opt_entry.get('ecs_source_prefix', 0)
        scope_prefix = opt_entry.get('ecs_scope_prefix', 0)
        addr_str = opt_entry.get('ecs_address', '0.0.0.0')
        addr = ipaddress.ip_address(addr_str)
        addr_bytes = addr.packed
        return struct.pack('!HBB', family, src_prefix, scope_prefix) + addr_bytes
    elif code == 3: # NSID
        nsid_str = opt_entry.get('nsid', '')
        return nsid_str.encode('ascii', errors='replace')
    elif code == 10: # COOKIE
        client = opt_entry.get('client_cookie', '')
        server = opt_entry.get('server_cookie', '')
        if server:
            return bytes.fromhex(client) + bytes.fromhex(server)
        elif client:
            return bytes.fromhex(client)
        else:
            return b''
    elif code == 5: # DAU
        algs = opt_entry.get('algorithms', [])
        return bytes(algs)
    elif code == 6: # DHU
        algs = opt_entry.get('hash_algorithms', [])
        return bytes(algs)
    return b''


def dict_to_wire(data: Dict[str, Any]) -> bytes:
    return dict_to_message(data).to_wire()

def send2upsteram(query_data,UPSTREAM):
    upstream_resp = requests.post(
                UPSTREAM,
                data=query_data,
                headers={'Content-Type': 'application/dns-message'},
                timeout=5
            )
    return upstream_resp

def build_query(n,t):
    query_dict={'header': {'id': 0, 'flags': ['RD'], 'opcode': 'QUERY', 'rcode': 'NOERROR', 'qdcount': 1, 'ancount': 0, 'nscount': 0, 'arcount': 0}, 'question': [{'name': '', 'type': '','class': 'IN'}], 'answer': [], 'authority': [], 'additional': []}
    query_dict['question'][0]['name'] = n
    query_dict['question'][0]['type'] = t
    return query_dict

def name_handler(dns_result,name_dict,cdn_dict):
    #name_dict={ 'example.com.':'cdn_provider'}
    #cdn_dict={'cdn_provider':'cdn_ech_domain'}

    dns_dict = r2d(dns_result)  
    name_chooser=(lambda d,n: [i for i in n.keys() if d.endswith(i)])
    mached_list=name_chooser(dns_dict['question'][0]['name'],name_dict)
    print(mached_list)
    print(dns_dict)
    
    if  mached_list == []:
        return dns_result
    sub_dict=name_dict[mached_list[0]]
    print(sub_dict)
    if dns_dict['question'][0]['type'] not in ['HTTPS','A','AAAA']:
        return dns_result
#    print(dns_dict)

        
    # 2. 检查是否已经存在包含 ECH 的有效回答
    if dns_dict['question'][0]['type']=='HTTPS':
        has_ech = False
        for ans in dns_dict.get('answer', []):
            if 'ech=' in ans.get('data', ''):
                has_ech = True
                break
        if has_ech:
            return dns_result   
            
    if sub_dict['ech_only']==1:
        if dns_dict['question'][0]['type']!='HTTPS':
            return dns_result
            
        def add_ech(dns_result,ech_pubkey,ttl):
    #print('\r\n\r\nMODIFIED\r\n\r\n')
            answer=copy.deepcopy(dns_result['question'][0])
    #print(answer)
            answer['data']='1 . ' + ech_pubkey
#            answer['data']=ech_pubkey
            answer['ttl']=ttl
            dns_result['answer']=[answer]
            dns_result['header']['ancount']=1
            dns_result['header']['nscount']=0
            dns_result['authority']=[]
            return dns_result
            
        n=cdn_dict[sub_dict['cdn']]
        t=dns_dict['question'][0]['type']
        query=build_query(n,t)
    
        try:
            print('ech query')
            dns_response=send2upsteram(d2r(query),UPSTREAM)
            print('ech query success')
        except requests.RequestException as e:
            print(f"Upstream error: {e}")
            return dns_result
            
        ech_res_dict=r2d(dns_response.content)
        print(ech_res_dict)
        ech_pubkey=(lambda s : [i for i in s.split(' ') if i.startswith('ech=')])(ech_res_dict['answer'][0]['data'])[0]
#    ech_pubkey=ech_res_dict['answer'][0]['data']
        print("\r\n\r\n\r\nTEST")    
        print(ech_res_dict)
        ttl=ech_res_dict['answer'][0]['ttl']
        modified_dns=add_ech(dns_dict,ech_pubkey,ttl)
        print(modified_dns)
        return d2r(modified_dns)

    if sub_dict['ech_only']==0:
        def answer_replace(old_data,fake_answer):
            answer=[]
            for i in fake_answer:
                if i['type'] not in ['A','AAAA','HTTPS']:
                    answer.append(i)
                else:        
                    i['name']=old_data['question'][0]['name']
                    answer.append(i)
            old_data['answer']=answer
            if old_data['question'][0]['type']=='HTTPS':
                old_data['header']['ancount']=1
                old_data['header']['nscount']=0
            old_data['authority']=[]
            return old_data
        
        n=cdn_dict[sub_dict['cdn']]
        t=dns_dict['question'][0]['type']
        query=build_query(n,t)
        print(query)
        try:
            print(t +' query')
            dns_response=send2upsteram(d2r(query),UPSTREAM)
        except requests.RequestException as e:
            print(f"Upstream error: {e}")
            return dns_result
        
        res_dict=r2d(dns_response.content)
        
        print(res_dict)
        modified_dns=answer_replace(dns_dict,res_dict['answer'])
        print(modified_dns)
        return d2r(modified_dns)
        
            
class MyHandler(BaseHTTPRequestHandler):

    def __send_json(self,dic,state=200):
        self.send_response(state)
        self.send_header('Content-type', 'application/dns-message')
        self.end_headers()
        self.wfile.write((json.dumps(dic)+ '\n').encode('utf-8'))
        
    def do_GET(self):
        path_l=self.path.split('/')
        path_l=[ i for i in path_l if i != '']
        print(path_l)
        self.send_error(200,'ok')

    


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
            upstream_resp=send2upsteram(query_data,UPSTREAM)
        except requests.RequestException as e:
            print(f"Upstream error: {e}")
            self.send_error(502, 'Bad Gateway')
            return


        self.send_response(upstream_resp.status_code)
        self.send_header('Content-Type', 'application/dns-message')
        self.end_headers()
        
        
        print('Res')
#        print(parse_dns_wire(upstream_resp.content))
        qd=name_handler(upstream_resp.content,name_dict,cdn_dict) 
        self.wfile.write(qd)
        #print(parse_dns_wire(upstream_resp.content))
        
        
UPSTREAM='https://name.yosakura.xyz/google/query-dns'
r2d=message_to_dict
d2r=dict_to_message

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
