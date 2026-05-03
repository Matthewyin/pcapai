#!/usr/bin/env python3
"""Generate a multi-fault pcap for pcapAI testing.

Scenario: Enterprise web service outage — client 192.168.1.100 accessing 60.205.91.221
Faults: DNS failures, TCP SYN loss, TLS handshake failure, RST, zero window, HTTP 502, ICMP unreachable
"""
import struct, os, time
from scapy.all import *

CLIENT = "192.168.1.100"
DNS_SERVER = "8.8.8.8"
SERVER = "60.205.91.221"
CLIENT_MAC = "aa:bb:cc:00:00:64"
SERVER_MAC = "aa:bb:cc:00:00:01"
DNS_MAC = "aa:bb:cc:00:00:08"

def to_client():
    return Ether(src=DNS_MAC if DNS_SERVER == "8.8.8.8" else SERVER_MAC, dst=CLIENT_MAC)

def to_server():
    return Ether(src=CLIENT_MAC, dst=SERVER_MAC)

def to_dns():
    return Ether(src=CLIENT_MAC, dst=DNS_MAC)

pkts = []
t = 1735000000.0  # fixed base time

def add(pkt, dt=0.001):
    global t
    t += dt
    pkt.time = t
    pkts.append(pkt)

# ── Phase 1: DNS failures ──────────────────────────────────────

# DNS query -> NXDOMAIN
add(to_dns()/IP(src=CLIENT, dst=DNS_SERVER)/UDP(sport=45123, dport=53)/
    DNS(id=0x1a2b, rd=1, qd=DNSQR(qname="api.example.com", qtype="A")), dt=0.05)

add(Ether(src=DNS_MAC, dst=CLIENT_MAC)/IP(src=DNS_SERVER, dst=CLIENT)/UDP(sport=53, dport=45123)/
    DNS(id=0x1a2b, qr=1, rcode=3, qd=DNSQR(qname="api.example.com", qtype="A"),
        ns=DNSRR(rrname="example.com", type="SOA", rdata="ns1.example.com")), dt=0.1)

# DNS retry -> SERVFAIL
add(to_dns()/IP(src=CLIENT, dst=DNS_SERVER)/UDP(sport=45124, dport=53)/
    DNS(id=0x2b3c, rd=1, qd=DNSQR(qname="api.example.com", qtype="A")), dt=0.15)

add(Ether(src=DNS_MAC, dst=CLIENT_MAC)/IP(src=DNS_SERVER, dst=CLIENT)/UDP(sport=53, dport=45124)/
    DNS(id=0x2b3c, qr=1, rcode=2, qd=DNSQR(qname="api.example.com", qtype="A")), dt=0.1)

# DNS retry 2 -> success
add(to_dns()/IP(src=CLIENT, dst=DNS_SERVER)/UDP(sport=45125, dport=53)/
    DNS(id=0x3c4d, rd=1, qd=DNSQR(qname="api.example.com", qtype="A")), dt=0.2)

add(Ether(src=DNS_MAC, dst=CLIENT_MAC)/IP(src=DNS_SERVER, dst=CLIENT)/UDP(sport=53, dport=45125)/
    DNS(id=0x3c4d, qr=1, rcode=0, ancount=2,
        qd=DNSQR(qname="api.example.com", qtype="A"),
        an=DNSRR(rrname="api.example.com", type="CNAME", rdata="lb.example.com")/
            DNSRR(rrname="lb.example.com", type="A", rdata=SERVER)), dt=0.05)

# ── Phase 2: TCP SYN loss (4 SYN, no SYN-ACK) ─────────────────

sport_syn = 50100
seq_syn = 1000
for i in range(4):
    add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=sport_syn, dport=443,
        seq=seq_syn, flags="S", window=65535,
        options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1000+i*500, 0))]), dt=1.0)

t += 3.5  # backoff timeout

# ── Phase 3: TCP handshake succeeds, TLS fails ────────────────

s = 50200; sq = 2000; saq = 3000

# 3-way handshake
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s, dport=443, seq=sq, flags="S", window=65535,
    options=[("MSS", 1460), ("WScale", 6), ("SAckOK", b""), ("Timestamp", (2000, 0))]))
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=443, dport=s, seq=saq, ack=sq+1, flags="SA", window=65535,
    options=[("MSS", 1460), ("WScale", 6), ("SAckOK", b""), ("Timestamp", (2001, 2000))]))
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s, dport=443, seq=sq+1, ack=saq+1, flags="A", window=1024,
    options=[("Timestamp", (2002, 2001))]))

# TLS ClientHello (simplified raw bytes)
ch_len = 200
client_hello = (b"\x16\x03\x01" + struct.pack(">H", ch_len) +
    b"\x01" + struct.pack(">I", ch_len - 4)[1:] +
    b"\x03\x03" + os.urandom(32) +
    b"\x00" +
    b"\x00\x02\x00\x2f" +
    b"\x01\x00" +
    b"\x00\x00")

add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s, dport=443, seq=sq+1, ack=saq+1, flags="PA", window=1024,
    options=[("Timestamp", (2003, 2001))])/Raw(load=client_hello))
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=443, dport=s, seq=saq+1, ack=sq+1+len(client_hello), flags="A", window=65535,
    options=[("Timestamp", (2004, 2003))]))

# TLS Alert: fatal handshake_failure (0x15=alert, 0x0303=TLS1.2, len=2, level=fatal(2), desc=handshake_failure(40))
tls_alert = b"\x15\x03\x03\x00\x02\x02\x28"
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=443, dport=s, seq=saq+1, ack=sq+1+len(client_hello), flags="PA", window=65535,
    options=[("Timestamp", (2005, 2003))])/Raw(load=tls_alert))
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s, dport=443, seq=sq+1+len(client_hello), ack=saq+1+len(tls_alert), flags="A", window=1024,
    options=[("Timestamp", (2006, 2005))]))

# FIN close
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s, dport=443, seq=sq+1+len(client_hello), ack=saq+1+len(tls_alert), flags="FA", window=1024,
    options=[("Timestamp", (2007, 2005))]))
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=443, dport=s, seq=saq+1+len(tls_alert), ack=sq+2+len(client_hello), flags="FA", window=65535,
    options=[("Timestamp", (2008, 2007))]))
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s, dport=443, seq=sq+2+len(client_hello), ack=saq+2+len(tls_alert), flags="A", window=1024,
    options=[("Timestamp", (2009, 2008))]))

# ── Phase 4: TCP RST after HTTP request ────────────────────────

s2 = 50300; sq2 = 4000; saq2 = 5000

add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s2, dport=80, seq=sq2, flags="S", window=65535,
    options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (3000, 0))]))
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=80, dport=s2, seq=saq2, ack=sq2+1, flags="SA", window=65535,
    options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (3001, 3000))]))
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s2, dport=80, seq=sq2+1, ack=saq2+1, flags="A", window=1024,
    options=[("Timestamp", (3002, 3001))]))

http_get = b"GET /api/v1/health HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: application/json\r\n\r\n"
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s2, dport=80, seq=sq2+1, ack=saq2+1, flags="PA", window=1024,
    options=[("Timestamp", (3003, 3001))])/Raw(load=http_get), dt=0.01)
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=80, dport=s2, seq=saq2+1, ack=sq2+1+len(http_get), flags="A", window=65535,
    options=[("Timestamp", (3004, 3003))]))

# RST from server
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=80, dport=s2, seq=saq2+1, flags="R", window=0,
    options=[("Timestamp", (3005, 3003))]), dt=0.01)

# ── Phase 5: HTTP 502 + Zero Window + retransmissions ─────────

s3 = 50400; sq3 = 6000; saq3 = 7000

add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s3, dport=80, seq=sq3, flags="S", window=65535,
    options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (4000, 0))]))
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=80, dport=s3, seq=saq3, ack=sq3+1, flags="SA", window=65535,
    options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (4001, 4000))]))
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s3, dport=80, seq=sq3+1, ack=saq3+1, flags="A", window=1024,
    options=[("Timestamp", (4002, 4001))]))

http_get2 = b"GET /api/v1/data HTTP/1.1\r\nHost: api.example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s3, dport=80, seq=sq3+1, ack=saq3+1, flags="PA", window=1024,
    options=[("Timestamp", (4003, 4001))])/Raw(load=http_get2), dt=0.01)
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=80, dport=s3, seq=saq3+1, ack=sq3+1+len(http_get2), flags="A", window=65535,
    options=[("Timestamp", (4004, 4003))]))

http_502 = b"HTTP/1.1 502 Bad Gateway\r\nServer: nginx/1.24\r\nContent-Type: text/html\r\nContent-Length: 166\r\n\r\n<html>\r\n<head><title>502 Bad Gateway</title></head>\r\n<body>\r\n<center><h1>502 Bad Gateway</h1></center>\r\n<hr><center>nginx/1.24</center>\r\n</body>\r\n</html>\r\n"
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=80, dport=s3, seq=saq3+1, ack=sq3+1+len(http_get2), flags="PA", window=65535,
    options=[("Timestamp", (4005, 4003))])/Raw(load=http_502), dt=0.005)
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s3, dport=80, seq=sq3+1+len(http_get2), ack=saq3+1+len(http_502), flags="A", window=1024,
    options=[("Timestamp", (4006, 4005))]))

# Second request -> server zero window
http_get3 = b"GET /api/v1/metrics HTTP/1.1\r\nHost: api.example.com\r\n\r\n"
add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s3, dport=80, seq=sq3+1+len(http_get2), ack=saq3+1+len(http_502), flags="PA", window=1024,
    options=[("Timestamp", (4007, 4005))])/Raw(load=http_get3), dt=0.005)

# Server ACK + zero window
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=80, dport=s3, seq=saq3+1+len(http_502), ack=sq3+1+len(http_get2)+len(http_get3), flags="A", window=0,
    options=[("Timestamp", (4008, 4007))]))

# Client retransmits 4 times (zero window probes)
for i in range(4):
    add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=s3, dport=80,
        seq=sq3+1+len(http_get2), ack=saq3+1+len(http_502), flags="PA", window=1024,
        options=[("Timestamp", (4009+i*200, 4008))])/Raw(load=http_get3), dt=0.2)

# Server window update then RST
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=80, dport=s3, seq=saq3+1+len(http_502), ack=sq3+1+len(http_get2)+len(http_get3), flags="A", window=65535,
    options=[("Timestamp", (4200, 4015))]), dt=0.01)
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/TCP(sport=80, dport=s3, seq=saq3+1+len(http_502), flags="R", window=0), dt=0.05)

# ── Phase 6: ICMP Unreachable ──────────────────────────────────

add(to_server()/IP(src=CLIENT, dst=SERVER)/TCP(sport=50500, dport=8080, seq=8000, flags="S", window=65535,
    options=[("MSS", 1460), ("Timestamp", (5000, 0))]))

# ICMP Destination Unreachable (Port Unreachable: type=3, code=3)
inner_tcp = TCP(sport=50500, dport=8080, seq=8000, flags="S")
add(Ether(src=SERVER_MAC, dst=CLIENT_MAC)/IP(src=SERVER, dst=CLIENT)/ICMP(type=3, code=3)/Raw(load=bytes(IP(src=CLIENT, dst=SERVER)/inner_tcp)[:28]), dt=0.01)

# Sort by time
pkts.sort(key=lambda p: float(p.time))

out = "/Users/matthewyin/Coding/pcapAI/data/fixtures/multi-fault-scenario.pcap"
wrpcap(out, pkts)
print(f"Written {len(pkts)} packets to {out}")
