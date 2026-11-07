"""Restricted Modbus TCP worker for the educational CPS dam Docker network.

Executed in the existing `attacker` container by traditional_multinode.py.
The executable on the host passes this file as the `python -c` program.
Only the two fixed, verified lab devices are reachable through this worker.
"""
import json
import socket
import struct
import sys
import time

TARGETS = {"device": "172.28.10.20", "inlet": "172.28.10.21"}
PORT = 5020
TIMEOUT = 1.5
EXCEPTIONS = {
    1: "illegal_function", 2: "illegal_data_address",
    3: "illegal_data_value", 4: "server_device_failure",
    5: "acknowledge", 6: "server_device_busy",
    8: "memory_parity_error", 10: "gateway_path_unavailable",
    11: "gateway_target_failed_to_respond",
}


def verify_scope():
    for name, ip in TARGETS.items():
        resolved = {
            info[4][0]
            for info in socket.getaddrinfo(name, PORT, socket.AF_INET, socket.SOCK_STREAM)
        }
        if resolved != {ip}:
            raise RuntimeError("Refusing out-of-scope target %s: %s" % (name, resolved))


def receive_exact(sock, count):
    data = bytearray()
    while len(data) < count:
        fragment = sock.recv(count - len(data))
        if not fragment:
            raise EOFError("Connection closed after %d of %d bytes" % (len(data), count))
        data.extend(fragment)
    return bytes(data)


def make_request(case):
    tid = int(case.get("tid", 0xA002))
    function = int(case.get("function", 4))
    address = int(case.get("address", 0))
    quantity = int(case.get("quantity", 1))
    value = int(case.get("value", 0))
    unit = int(case.get("unit", 1))
    proto = int(case.get("proto", 0))
    if function in (3, 4):
        pdu = struct.pack("!BHH", function, address, quantity)
    elif function == 6:
        pdu = struct.pack("!BHH", function, address, value)
    elif function == 127:
        pdu = b"\x7f"
    else:
        raise ValueError("Function not included in restricted test suite")
    length = int(case.get("length_override", 1 + len(pdu)))
    packet = struct.pack("!HHHB", tid, proto, length, unit) + pdu
    return packet, pdu


def exchange(case):
    name = case["target"]
    if name not in TARGETS:
        raise ValueError("Target not in allowed dam lab targets")
    if int(case.get("function", 4)) == 6 and not case.get("write_opt_in", False):
        raise ValueError("Actuator write requires explicit write_opt_in")
    request, pdu = make_request(case)
    began = time.monotonic()
    result = {
        "target": name, "result": "unknown", "exception_code": "",
        "exception_name": "", "detail": "", "values": [],
        "request_hex": request.hex(), "response_hex": "", "latency_ms": 0.0,
    }
    try:
        with socket.create_connection((TARGETS[name], PORT), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)
            sock.sendall(request)
            header = receive_exact(sock, 7)
            tid, proto, length, unit = struct.unpack("!HHHB", header)
            if length < 2 or length > 254:
                raise ValueError("Invalid response length field %d" % length)
            payload = receive_exact(sock, length - 1)
        result["response_hex"] = (header + payload).hex()
        requested_tid = int(case.get("tid", 0xA002))
        requested_unit = int(case.get("unit", 1))
        if (tid, proto, unit) != (requested_tid, 0, requested_unit):
            raise ValueError("Response transaction/protocol/unit mismatch")
        function = int(case.get("function", 4))
        if payload[0] == (function | 0x80):
            if len(payload) != 2:
                raise ValueError("Incorrect exception response length")
            code = payload[1]
            result["result"] = "modbus_exception"
            result["exception_code"] = code
            result["exception_name"] = EXCEPTIONS.get(code, "unknown_exception")
        elif function in (3, 4) and payload[0] == function:
            count = int(case.get("quantity", 1))
            if (len(payload) < 2 or payload[1] != count * 2
                    or len(payload) != 2 + count * 2):
                raise ValueError("Incorrect response byte count")
            result["result"] = "normal_response"
            if count:
                result["values"] = list(struct.unpack("!%dH" % count, payload[2:]))
        elif function == 6 and payload == pdu:
            result["result"] = "write_accepted"
        else:
            result["result"] = "unexpected_response"
            result["detail"] = "Unexpected function or response payload"
    except socket.timeout:
        result["result"] = "timeout"
        result["detail"] = "No complete reply before timeout"
    except EOFError as exc:
        result["result"] = "connection_closed"
        result["detail"] = str(exc)
    except (OSError, ValueError) as exc:
        result["result"] = "protocol_or_connection_error"
        result["detail"] = str(exc)
    result["latency_ms"] = round((time.monotonic() - began) * 1000, 2)
    return result


def snapshot():
    readings = {}
    for name in TARGETS:
        case = {"target": name, "function": 4, "address": 0, "quantity": 2}
        readings[name] = exchange(case)
    return readings


def emit(value):
    print(json.dumps(value, separators=(",", ":")), flush=True)


def main():
    try:
        verify_scope()
    except Exception as exc:
        emit({"event": "fatal", "error": str(exc)})
        return 2
    emit({"event": "ready", "targets": TARGETS})
    for line in sys.stdin:
        try:
            request = json.loads(line)
            operation = request.get("operation")
            if operation == "stop":
                emit({"event": "stopped"})
                return 0
            if operation == "snapshot":
                emit({"event": "snapshot", "readings": snapshot()})
            elif operation == "fuzz":
                emit({"event": "fuzz", "data": exchange(request["case"])})
            else:
                emit({"event": "error", "error": "Unknown operation"})
        except Exception as exc:
            emit({"event": "error", "error": str(exc)})
    return 0


if __name__ == "__main__":
    sys.exit(main())
