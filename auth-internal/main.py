import os
import socket
import time
import threading

import yaml
from dnslib import DNSRecord, RR, A, NS, CNAME, QTYPE, RCODE

LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 33053
RECORDS_FILE = "records.yaml"


def normalize_name(name: str) -> str:
    return name.rstrip(".").lower()


def find_delegation(qname: str, records: dict[tuple[str, str], dict]):
    for (name, record_type), record in records.items():
        if record_type != "NS":
            continue

        if qname == name or qname.endswith("." + name):
            return name, record

    return None


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


def add_glue_record(
    response: DNSRecord,
    ns_name: str,
    records: dict[tuple[str, str], dict],
) -> None:
    normalized_ns_name = normalize_name(ns_name)
    glue_record = records.get((normalized_ns_name, "A"))

    if glue_record is None:
        print(f"glue not found ns={normalized_ns_name}")
        return

    response.add_ar(
        RR(
            rname=normalized_ns_name + ".",
            rtype=QTYPE.A,
            rclass=1,
            ttl=glue_record["ttl"],
            rdata=A(glue_record["value"]),
        )
    )

    print(
        f"glue name={normalized_ns_name} "
        f"value={glue_record['value']}"
    )

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
        delegation = find_delegation(qname, records)

        if delegation is not None:
            delegated_name, ns_record = delegation

            response.header.rcode = RCODE.NOERROR
            response.add_auth(
                RR(
                    rname=delegated_name + ".",
                    rtype=QTYPE.NS,
                    rclass=1,
                    ttl=ns_record["ttl"],
                    rdata=NS(ns_record["value"]),
                )
            )

            add_glue_record(response, ns_record["value"], records)

            print(f"delegation name={delegated_name} ns={ns_record['value']}")
            return response
        
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

    if qtype == "CNAME":
        response.add_answer(
            RR(
                rname=question.qname,
                rtype=QTYPE.CNAME,
                rclass=1,
                ttl=record["ttl"],
                rdata=CNAME(record["value"]),
            )
        )

        print(
            f"cname name={qname} "
            f"alias={record['value']}"
        )

        return response

    response.header.rcode = RCODE.NXDOMAIN
    return response


def apply_mode(mode: str) -> bool:
    if mode == "slow":
        print("slow mode: sleep 5 seconds")
        time.sleep(5)

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