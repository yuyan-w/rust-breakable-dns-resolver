import os
import random
import socket
import struct
import threading
import time

import yaml
from dnslib import (
    A,
    CNAME,
    DNSRecord,
    NS,
    QTYPE,
    RCODE,
    RR,
    TXT,
)

LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 33053
RECORDS_FILE = "records.yaml"

MAX_UDP_SIZE = 512
TXT_CHUNK_SIZE = 255
TCP_RECV_SIZE = 4096


def normalize_name(name: str) -> str:
    return name.rstrip(".").lower()


def split_txt_value(value: str) -> list[str]:
    text = "".join(value.splitlines())

    return [
        text[index : index + TXT_CHUNK_SIZE]
        for index in range(0, len(text), TXT_CHUNK_SIZE)
    ]


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


def build_response(
    request: DNSRecord,
    records: dict[tuple[str, str], dict],
) -> DNSRecord:
    question = request.q
    qname = normalize_name(str(question.qname))
    qtype = QTYPE[question.qtype]

    response = request.reply()
    response.header.aa = 1
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

            print(
                f"delegation name={delegated_name} "
                f"ns={ns_record['value']}"
            )

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

        print(
            f"answer name={qname} "
            f"value={record['value']}"
        )

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

    if qtype == "TXT":
        chunks = split_txt_value(record["value"])

        response.add_answer(
            RR(
                rname=question.qname,
                rtype=QTYPE.TXT,
                rclass=1,
                ttl=record["ttl"],
                rdata=TXT(chunks),
            )
        )

        print(
            f"txt name={qname} "
            f"size={len(record['value'])} "
            f"chunks={len(chunks)}"
        )

        return response

    response.header.rcode = RCODE.NXDOMAIN
    return response


def truncate_udp_response_if_needed(
    request: DNSRecord,
    response: DNSRecord,
) -> DNSRecord:
    packed = response.pack()

    if len(packed) <= MAX_UDP_SIZE:
        return response

    truncated = request.reply()
    truncated.header.aa = response.header.aa
    truncated.header.ra = response.header.ra
    truncated.header.rcode = response.header.rcode
    truncated.header.tc = 1

    print(
        f"truncate udp response "
        f"size={len(packed)} "
        f"max={MAX_UDP_SIZE}"
    )

    return truncated


def apply_mode(mode: str) -> bool:
    if mode == "slow":
        print("slow mode: sleep 2 seconds")
        time.sleep(2)

    if mode == "drop":
        print("drop mode: no response")
        return False

    if mode == "flaky":
        if random.random() < 0.5:
            print("flaky mode: sleep 3 seconds")
            time.sleep(3)
        else:
            print("flaky mode: normal response")

    return True


def receive_exactly(conn: socket.socket, size: int) -> bytes:
    chunks = []

    remaining = size

    while remaining > 0:
        chunk = conn.recv(remaining)

        if not chunk:
            raise ConnectionError("connection closed")

        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def handle_udp_request(sock, data, addr, records, mode):
    try:
        request = DNSRecord.parse(data)
    except Exception as error:
        print(f"udp parse error: {error}")
        return

    should_respond = apply_mode(mode)

    if not should_respond:
        return

    response = build_response(request, records)
    response = truncate_udp_response_if_needed(
        request,
        response,
    )

    sock.sendto(response.pack(), addr)

    print(f"sent udp response to {addr}")


def handle_tcp_connection(conn, addr, records, mode):
    with conn:
        try:
            length_bytes = receive_exactly(conn, 2)
            request_length = struct.unpack("!H", length_bytes)[0]
            request_data = receive_exactly(conn, request_length)

            request = DNSRecord.parse(request_data)

            should_respond = apply_mode(mode)

            if not should_respond:
                return

            response = build_response(request, records)
            response_data = response.pack()
            response_length = struct.pack("!H", len(response_data))

            conn.sendall(response_length + response_data)

            print(
                f"sent tcp response to {addr} "
                f"size={len(response_data)}"
            )

        except Exception as error:
            print(f"tcp error addr={addr} error={error}")


def serve_udp(records, mode):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))

    print(f"start udp={LISTEN_ADDR}:{LISTEN_PORT}")

    while True:
        data, addr = sock.recvfrom(TCP_RECV_SIZE)

        thread = threading.Thread(
            target=handle_udp_request,
            args=(sock, data, addr, records, mode),
        )

        thread.start()


def serve_tcp(records, mode):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))
    sock.listen()

    print(f"start tcp={LISTEN_ADDR}:{LISTEN_PORT}")

    while True:
        conn, addr = sock.accept()

        thread = threading.Thread(
            target=handle_tcp_connection,
            args=(conn, addr, records, mode),
        )

        thread.start()


def main() -> None:
    mode = os.getenv("AUTH_MODE", "normal")
    records = load_records()

    print(f"mode={mode}")
    print(f"records={len(records)}")

    udp_thread = threading.Thread(
        target=serve_udp,
        args=(records, mode),
    )

    tcp_thread = threading.Thread(
        target=serve_tcp,
        args=(records, mode),
    )

    udp_thread.start()
    tcp_thread.start()

    udp_thread.join()
    tcp_thread.join()


if __name__ == "__main__":
    main()
