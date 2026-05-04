#!/usr/bin/env python3
"""Generate SaaS platform cascade fault pcap for pcapAI demo.

Scenario: Client 10.0.2.50 accessing app.cloudservice.io
Nodes: DNS=10.0.1.1, CDN/LB=203.0.113.80, API=198.51.100.10, Router=10.0.2.1

Faults:
  1. DNS timeout + NXDOMAIN + CNAME chain success
  2. TCP SYN retry (CDN) + SYN loss (API)
  3. TLS version downgrade + cert SAN mismatch
  4. HTTP 301/401/503/502 cascade
  5. TCP window shrinking + zero window + retransmission
  6. ICMP Host Unreachable + Fragmentation Needed
"""
import struct, os
from scapy.all import *

CLIENT = "10.0.2.50"
DNS_SERVER = "10.0.1.1"
CDN = "203.0.113.80"
API = "198.51.100.10"
ROUTER = "10.0.2.1"

CLIENT_MAC = "aa:bb:cc:00:02:32"
DNS_MAC = "aa:bb:cc:00:01:01"
CDN_MAC = "aa:bb:cc:00:43:50"
API_MAC = "aa:bb:cc:00:c6:0a"
ROUTER_MAC = "aa:bb:cc:00:02:01"

pkts = []
t = 1736000000.0

def add(pkt, dt=0.001):
    global t
    t += dt
    pkt.time = t
    pkts.append(pkt)

def eth(src, dst):
    return Ether(src=src, dst=dst)

# ── Phase 1: DNS ──────────────────────────────────────────────

# Query 1: timeout (no response)
add(eth(CLIENT_MAC, DNS_MAC)/IP(src=CLIENT, dst=DNS_SERVER)/UDP(sport=43123, dport=53)/
    DNS(id=0xA001, rd=1, qd=DNSQR(qname="app.cloudservice.io", qtype="A")), dt=0.05)
t += 2.0  # 2s timeout

# Query 2: NXDOMAIN
add(eth(CLIENT_MAC, DNS_MAC)/IP(src=CLIENT, dst=DNS_SERVER)/UDP(sport=43124, dport=53)/
    DNS(id=0xA002, rd=1, qd=DNSQR(qname="app.cloudservice.io", qtype="A")), dt=0.05)
add(eth(DNS_MAC, CLIENT_MAC)/IP(src=DNS_SERVER, dst=CLIENT)/UDP(sport=53, dport=43124)/
    DNS(id=0xA002, qr=1, rcode=3, qd=DNSQR(qname="app.cloudservice.io", qtype="A"),
        ns=DNSRR(rrname="cloudservice.io", type="SOA", rdata="ns1.cloudservice.io")), dt=0.15)

# Query 3: success with CNAME chain
add(eth(CLIENT_MAC, DNS_MAC)/IP(src=CLIENT, dst=DNS_SERVER)/UDP(sport=43125, dport=53)/
    DNS(id=0xA003, rd=1, qd=DNSQR(qname="app.cloudservice.io", qtype="A")), dt=0.1)
add(eth(DNS_MAC, CLIENT_MAC)/IP(src=DNS_SERVER, dst=CLIENT)/UDP(sport=53, dport=43125)/
    DNS(id=0xA003, qr=1, rcode=0, ancount=2,
        qd=DNSQR(qname="app.cloudservice.io", qtype="A"),
        an=DNSRR(rrname="app.cloudservice.io", type="CNAME", rdata="cdn.cloudservice.io")/
            DNSRR(rrname="cdn.cloudservice.io", type="A", rdata=CDN)), dt=0.03)

# ── Phase 2: TCP connections ──────────────────────────────────

# To CDN: SYN retry (3 SYN, then SYN/ACK)
s_cdn = 51000; sq_cdn = 10000; saq_cdn = 20000
for i in range(3):
    add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_cdn, dport=443,
        seq=sq_cdn, flags="S", window=65535,
        options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1000+i*500, 0))]), dt=0.8)

# SYN/ACK after 3rd retry
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=443, dport=s_cdn,
    seq=saq_cdn, ack=sq_cdn+1, flags="SA", window=65535,
    options=[("MSS", 1460), ("WScale", 6), ("SAckOK", b""), ("Timestamp", (2501, 2000))]))
# ACK
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_cdn, dport=443,
    seq=sq_cdn+1, ack=saq_cdn+1, flags="A", window=4096,
    options=[("Timestamp", (2502, 2501))]))

# To API: 4 SYN, no SYN/ACK
s_api = 52000; sq_api = 30000
for i in range(4):
    add(eth(CLIENT_MAC, API_MAC)/IP(src=CLIENT, dst=API)/TCP(sport=s_api+i, dport=8443,
        seq=sq_api+i, flags="S", window=65535,
        options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (3000+i*500, 0))]), dt=1.0)

t += 2.0  # backoff

# ── Phase 3: TLS ──────────────────────────────────────────────

# ClientHello (TLS 1.3 supported versions: 0x0304 in extensions)
ch_len = 250
client_hello = (
    b"\x16\x03\x01" + struct.pack(">H", ch_len) +
    b"\x01" + struct.pack(">I", ch_len - 4)[1:] +
    b"\x03\x03" + os.urandom(32) +
    b"\x20" + os.urandom(32) +
    b"\x00\x2c\xc0\x2c\xc0\x2b\xc0\x30\xc0\x2f\x00\x9e\x00\x9f\x00\x9c\x00\x9d"
    b"\x00\x01\x00" +
    b"\x00\x00\x00\x00\x00\x0f\x00\x0d\x00\x00\x0a" + os.urandom(10) +
    b"\x00\x0b\x00\x04\x03\x00\x01\x02"
)

add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_cdn, dport=443,
    seq=sq_cdn+1, ack=saq_cdn+1, flags="PA", window=4096,
    options=[("Timestamp", (5000, 2501))])/Raw(load=client_hello))
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=443, dport=s_cdn,
    seq=saq_cdn+1, ack=sq_cdn+1+len(client_hello), flags="A", window=65535,
    options=[("Timestamp", (5001, 5000))]))

# ServerHello (TLS 1.2 downgrade: version 0x0303, weak cipher 0x002f = TLS_RSA_WITH_AES_128_CBC_SHA)
sh_len = 80
server_hello = (
    b"\x16\x03\x03" + struct.pack(">H", sh_len) +
    b"\x02" + struct.pack(">I", sh_len - 4)[1:] +
    b"\x03\x03" + os.urandom(32) +
    b"\x00\x2f" +  # cipher: TLS_RSA_WITH_AES_128_CBC_SHA
    b"\x00" +
    b"\x00\x00\x00"
)

add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=443, dport=s_cdn,
    seq=saq_cdn+1, ack=sq_cdn+1+len(client_hello), flags="PA", window=65535,
    options=[("Timestamp", (5002, 5000))])/Raw(load=server_hello))
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_cdn, dport=443,
    seq=sq_cdn+1+len(client_hello), ack=saq_cdn+1+len(server_hello), flags="A", window=4096,
    options=[("Timestamp", (5003, 5002))]))

# TLS Fatal Alert: unrecognized_name (level=fatal=2, desc=unrecognized_name=112)
tls_alert = b"\x15\x03\x03\x00\x02\x02\x70"
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=443, dport=s_cdn,
    seq=saq_cdn+1+len(server_hello), ack=sq_cdn+1+len(client_hello), flags="PA", window=65535,
    options=[("Timestamp", (5004, 5003))])/Raw(load=tls_alert))
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_cdn, dport=443,
    seq=sq_cdn+1+len(client_hello), ack=saq_cdn+1+len(server_hello)+len(tls_alert), flags="A", window=4096,
    options=[("Timestamp", (5005, 5004))]))

# FIN close
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_cdn, dport=443,
    seq=sq_cdn+1+len(client_hello), ack=saq_cdn+1+len(server_hello)+len(tls_alert), flags="FA", window=4096,
    options=[("Timestamp", (5006, 5004))]))
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=443, dport=s_cdn,
    seq=saq_cdn+1+len(server_hello)+len(tls_alert), ack=sq_cdn+2+len(client_hello), flags="FA", window=65535,
    options=[("Timestamp", (5007, 5006))]))
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_cdn, dport=443,
    seq=sq_cdn+2+len(client_hello), ack=saq_cdn+2+len(server_hello)+len(tls_alert), flags="A", window=4096,
    options=[("Timestamp", (5008, 5007))]))

# ── Phase 4+5: HTTP cascade + TCP degradation ────────────────

# New TCP connection to CDN:80 for HTTP
s_http = 53000; sq_h = 40000; saq_h = 50000

add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h, flags="S", window=65535,
    options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (6000, 0))]))
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h, ack=sq_h+1, flags="SA", window=65535,
    options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (6001, 6000))]))
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h+1, ack=saq_h+1, flags="A", window=8192,
    options=[("Timestamp", (6002, 6001))]))

# GET / → 301 redirect
http_get1 = b"GET / HTTP/1.1\r\nHost: app.cloudservice.io\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html\r\n\r\n"
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h+1, ack=saq_h+1, flags="PA", window=8192,
    options=[("Timestamp", (6003, 6001))])/Raw(load=http_get1), dt=0.01)
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h+1, ack=sq_h+1+len(http_get1), flags="A", window=65535,
    options=[("Timestamp", (6004, 6003))]))

http_301 = b"HTTP/1.1 301 Moved Permanently\r\nLocation: /login\r\nContent-Length: 0\r\n\r\n"
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h+1, ack=sq_h+1+len(http_get1), flags="PA", window=65535,
    options=[("Timestamp", (6005, 6003))])/Raw(load=http_301), dt=0.005)
sq_h_resp = sq_h + 1 + len(http_get1)
saq_h_resp = saq_h + 1 + len(http_301)
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp, ack=saq_h_resp, flags="A", window=8192,
    options=[("Timestamp", (6006, 6005))]))

# GET /login → 200 OK (slow, 2s)
http_get2 = b"GET /login HTTP/1.1\r\nHost: app.cloudservice.io\r\nCookie: sid=abc123\r\n\r\n"
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp, ack=saq_h_resp, flags="PA", window=8192,
    options=[("Timestamp", (6007, 6005))])/Raw(load=http_get2), dt=0.01)
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp, ack=sq_h_resp+len(http_get2), flags="A", window=65535,
    options=[("Timestamp", (6008, 6007))]))

# Server window starts shrinking
http_200 = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 512\r\n\r\n" + b"<html>" + b"A" * 506 + b"</html>"
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp, ack=sq_h_resp+len(http_get2), flags="PA", window=16384,
    options=[("Timestamp", (6009, 6007))])/Raw(load=http_200), dt=2.0)  # slow response
sq_h_resp2 = sq_h_resp + len(http_get2)
saq_h_resp2 = saq_h_resp + len(http_200)
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp2, ack=saq_h_resp2, flags="A", window=8192,
    options=[("Timestamp", (6010, 6009))]))

# POST /api/auth → 401
http_post = b"POST /api/auth HTTP/1.1\r\nHost: app.cloudservice.io\r\nContent-Type: application/json\r\nCookie: sid=abc123\r\nContent-Length: 35\r\n\r\n{\"username\":\"user\",\"password\":\"old\"}"
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp2, ack=saq_h_resp2, flags="PA", window=8192,
    options=[("Timestamp", (6011, 6009))])/Raw(load=http_post), dt=0.01)
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp2, ack=sq_h_resp2+len(http_post), flags="A", window=4096,
    options=[("Timestamp", (6012, 6011))]))

http_401 = b"HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 28\r\n\r\n{\"error\":\"token_expired\"}"
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp2, ack=sq_h_resp2+len(http_post), flags="PA", window=4096,
    options=[("Timestamp", (6013, 6011))])/Raw(load=http_401), dt=0.005)
sq_h_resp3 = sq_h_resp2 + len(http_post)
saq_h_resp3 = saq_h_resp2 + len(http_401)
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp3, ack=saq_h_resp3, flags="A", window=8192,
    options=[("Timestamp", (6014, 6013))]))

# GET /api/dashboard → 503
http_get3 = b"GET /api/dashboard HTTP/1.1\r\nHost: app.cloudservice.io\r\nCookie: sid=abc123\r\n\r\n"
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp3, ack=saq_h_resp3, flags="PA", window=8192,
    options=[("Timestamp", (6015, 6013))])/Raw(load=http_get3), dt=0.01)
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp3, ack=sq_h_resp3+len(http_get3), flags="A", window=2048,
    options=[("Timestamp", (6016, 6015))]))

http_503 = b"HTTP/1.1 503 Service Unavailable\r\nServer: nginx/1.25\r\nContent-Type: text/html\r\nContent-Length: 70\r\n\r\n<html><body><h1>Service Unavailable</h1><p>Retry later</p></body></html>"
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp3, ack=sq_h_resp3+len(http_get3), flags="PA", window=2048,
    options=[("Timestamp", (6017, 6015))])/Raw(load=http_503), dt=0.01)
sq_h_resp4 = sq_h_resp3 + len(http_get3)
saq_h_resp4 = saq_h_resp3 + len(http_503)
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp4, ack=saq_h_resp4, flags="A", window=8192,
    options=[("Timestamp", (6018, 6017))]))

# Retry → 502
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp4, ack=saq_h_resp4, flags="PA", window=8192,
    options=[("Timestamp", (6019, 6017))])/Raw(load=http_get3), dt=0.01)
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp4, ack=sq_h_resp4+len(http_get3), flags="A", window=1024,
    options=[("Timestamp", (6020, 6019))]))

http_502 = b"HTTP/1.1 502 Bad Gateway\r\nServer: nginx/1.25\r\nContent-Type: text/html\r\nContent-Length: 62\r\n\r\n<html><body><h1>502 Bad Gateway</h1></body></html>"
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp4, ack=sq_h_resp4+len(http_get3), flags="PA", window=1024,
    options=[("Timestamp", (6021, 6019))])/Raw(load=http_502), dt=0.01)
sq_h_resp5 = sq_h_resp4 + len(http_get3)
saq_h_resp5 = saq_h_resp4 + len(http_502)
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp5, ack=saq_h_resp5, flags="A", window=8192,
    options=[("Timestamp", (6022, 6021))]))

# Retry again → 502
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp5, ack=saq_h_resp5, flags="PA", window=8192,
    options=[("Timestamp", (6023, 6021))])/Raw(load=http_get3), dt=0.01)
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp5, ack=sq_h_resp5+len(http_get3), flags="A", window=0,
    options=[("Timestamp", (6024, 6023))]))

http_502b = b"HTTP/1.1 502 Bad Gateway\r\nServer: nginx/1.25\r\nContent-Type: text/html\r\nContent-Length: 62\r\n\r\n<html><body><h1>502 Bad Gateway</h1></body></html>"
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp5, ack=sq_h_resp5+len(http_get3), flags="PA", window=0,
    options=[("Timestamp", (6025, 6023))])/Raw(load=http_502b), dt=0.01)
sq_h_resp6 = sq_h_resp5 + len(http_get3)
saq_h_resp6 = saq_h_resp5 + len(http_502b)

# Client retransmits (zero window probe)
for i in range(3):
    add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
        seq=sq_h_resp6, ack=saq_h_resp6, flags="A", window=8192,
        options=[("Timestamp", (6026+i*200, 6025))]), dt=0.3)

# Server window update
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp6, ack=sq_h_resp6, flags="A", window=65535,
    options=[("Timestamp", (6100, 6085))]), dt=0.01)

# FIN close
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp6, ack=saq_h_resp6, flags="FA", window=8192,
    options=[("Timestamp", (6101, 6100))]))
add(eth(CDN_MAC, CLIENT_MAC)/IP(src=CDN, dst=CLIENT)/TCP(sport=80, dport=s_http,
    seq=saq_h_resp6, ack=sq_h_resp6+1, flags="FA", window=65535,
    options=[("Timestamp", (6102, 6101))]))
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN)/TCP(sport=s_http, dport=80,
    seq=sq_h_resp6+1, ack=saq_h_resp6+1, flags="A", window=8192,
    options=[("Timestamp", (6103, 6102))]))

# ── Phase 6: ICMP ─────────────────────────────────────────────

# Client tries to reach API directly
add(eth(CLIENT_MAC, ROUTER_MAC)/IP(src=CLIENT, dst=API)/TCP(sport=54000, dport=8443,
    seq=60000, flags="S", window=65535,
    options=[("MSS", 1460), ("Timestamp", (7000, 0))]))

# ICMP Host Unreachable from router
inner_tcp = TCP(sport=54000, dport=8443, seq=60000, flags="S")
icmp_inner = bytes(IP(src=CLIENT, dst=API, ttl=64)/inner_tcp)[:28]
add(eth(ROUTER_MAC, CLIENT_MAC)/IP(src=ROUTER, dst=CLIENT)/ICMP(type=3, code=1)/Raw(load=icmp_inner), dt=0.005)

# PMTU failure: client sends large packet with DF
add(eth(CLIENT_MAC, CDN_MAC)/IP(src=CLIENT, dst=CDN, flags="DF")/TCP(sport=55000, dport=443,
    seq=70000, flags="S", window=65535,
    options=[("MSS", 1460), ("Timestamp", (7100, 0))])/Raw(load=b"A"*1200))

# ICMP Fragmentation Needed
inner_ip = IP(src=CLIENT, dst=CDN, flags="DF")
inner_tcp2 = TCP(sport=55000, dport=443, seq=70000, flags="S")
icmp_inner2 = bytes(inner_ip/inner_tcp2)[:28]
add(eth(ROUTER_MAC, CLIENT_MAC)/IP(src=ROUTER, dst=CLIENT)/ICMP(type=3, code=4)/Raw(load=icmp_inner2), dt=0.005)

# Sort by time
pkts.sort(key=lambda p: float(p.time))

out = "/Users/matthewyin/Coding/pcapAI/data/fixtures/saas-cascade-fault.pcap"
wrpcap(out, pkts)
print(f"Written {len(pkts)} packets to {out}")
