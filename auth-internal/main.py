import os
import socket
import time
import threading

import yaml
from dnslib import DNSRecord, RR, A, QTYPE, RCODE


LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 33053
RECORDS_FILE = "records.yaml"


def normalize_name(name: str) -> str:
    return name.rstrip(".").lower()


def load_records() -> dict[tuple[str, str], dict]:
    with open(RECORDS_FILE, "r", encoding="utf-8") as file:
        data = yaml.safe_load(file)

    records = {}

    for record in data.get("records", []):
        name = normalize_name(record["name"])
        record_type = record["type"].upper()

        records[(name, record_type)] = {
            "value": record["value"],
            "ttl": int(record.get("ttl", 30)),
        }

    return records


def build_response(request: DNSRecord, records: dict[tuple[str, str], dict]) -> DNSRecord:
    question = request.q
    qname = normalize_name(str(question.qname))
    qtype = QTYPE[question.qtype]

    response = request.reply()

    # 権威DNSとして応答する
    response.header.aa = 1

    # 再帰問い合わせはしない
    response.header.ra = 0

    print(f"query name={qname} type={qtype}")

    record = records.get((qname, qtype))

    if record is None:
        name_exists = any(name == qname for name, _ in records.keys())

        if name_exists:
            response.header.rcode = RCODE.NOERROR
            print(f"NODATA name={qname} type={qtype}")
            return response

        response.header.rcode = RCODE.NXDOMAIN
        print(f"NXDOMAIN name={qname}")
        return response

    if qtype == "A":
        response.add_answer(
            RR(
                rname=question.qname,
                rtype=QTYPE.A,
                rclass=1,
                ttl=record["ttl"],
                rdata=A(record["value"]),
            )
        )
        print(f"answer name={qname} value={record['value']}")
        return response

    response.header.rcode = RCODE.NXDOMAIN
    return response


def apply_mode(mode: str) -> bool:
    if mode == "slow":
        print("slow mode: sleep 2 seconds")
        time.sleep(2)

    if mode == "drop":
        print("drop mode: no response")
        return False

    return True

def handle_request(sock, data, addr, records, mode):
    try:
        request = DNSRecord.parse(data)
    except Exception as error:
        print(f"parse error: {error}")
        return

    should_respond = apply_mode(mode)
    if not should_respond:
        return

    response = build_response(request, records)
    sock.sendto(response.pack(), addr)

    print(f"sent response to {addr}")

def main() -> None:
    mode = os.getenv("AUTH_MODE", "normal")
    records = load_records()

    print(f"start udp={LISTEN_ADDR}:{LISTEN_PORT}")
    print(f"mode={mode}")
    print(f"records={len(records)}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))

    while True:
        data, addr = sock.recvfrom(512)

        thread = threading.Thread(
            target=handle_request,
            args=(sock, data, addr, records, mode),
        )
        thread.start()


if __name__ == "__main__":
    main()