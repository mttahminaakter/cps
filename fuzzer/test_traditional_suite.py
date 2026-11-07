"""Offline tests: no Docker or real dam services are contacted."""
import argparse
import csv
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import socket
import socketserver
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

import modbus_worker as worker
import traditional_multinode as suite


class FragmentedSocket:
    def __init__(self, parts):
        self.parts = list(parts)
    def recv(self, n):
        if not self.parts:
            return b""
        return self.parts.pop(0)


class FakeModbusHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(1)
        try:
            request = worker.receive_exact(self.request, 12)
        except Exception:
            return
        tid, proto, length, unit = struct.unpack("!HHHB", request[:7])
        function, address, quantity = struct.unpack("!BHH", request[7:])
        if function == 4 and 1 <= quantity <= 2 and address + quantity <= 2:
            values = (6525, 25)[address:address + quantity]
            pdu = bytes([4, 2 * quantity]) + struct.pack("!%dH" % quantity, *values)
        else:
            pdu = bytes([function | 0x80, 2])
        reply = struct.pack("!HHHB", tid, 0, 1 + len(pdu), unit) + pdu
        self.request.sendall(reply[:3])
        self.request.sendall(reply[3:])


class FakeHTTPHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'{"water_level":65.25,"actual_gate":25,"inlet_actual":100}'
        if self.path == "/api/state":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        elif self.path == "/":
            body = b"<html>OK</html>"
            self.send_response(200)
        else:
            self.send_response(404)
            body = b"Not Found"
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class TestProtocols(unittest.TestCase):
    def test_exact_modbus_request(self):
        packet, pdu = worker.make_request({"target": "inlet", "function": 4,
                                           "address": 0, "quantity": 2})
        self.assertEqual(packet, struct.pack("!HHHBBHH", 0xA002, 0, 6, 1, 4, 0, 2))
        self.assertEqual(len(pdu), 5)

    def test_fragmented_response_and_truncation(self):
        self.assertEqual(worker.receive_exact(FragmentedSocket([b"ab", b"c", b"d"]), 4), b"abcd")
        with self.assertRaises(EOFError):
            worker.receive_exact(FragmentedSocket([b"ab"]), 4)

    def test_modbus_full_frame_and_exceptions(self):
        server = socketserver.TCPServer(("127.0.0.1", 0), FakeModbusHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with patch.dict(worker.TARGETS, {"inlet": "127.0.0.1"}, clear=True), patch.object(worker, "PORT", server.server_address[1]):
            valid = worker.exchange({"target": "inlet", "function": 4, "address": 0, "quantity": 2})
            bad = worker.exchange({"target": "inlet", "function": 4, "address": 99, "quantity": 1})
        server.shutdown()
        server.server_close()
        self.assertEqual(valid["result"], "normal_response")
        self.assertEqual(valid["values"], [6525, 25])
        self.assertEqual(bad["result"], "modbus_exception")
        self.assertEqual(bad["exception_code"], 2)

    def test_default_campaign_has_no_writes(self):
        import random
        cases = suite.modbus_cases("inlet", 50, random.Random(42))
        self.assertEqual(len(cases), 50)
        self.assertFalse(any(c["function"] == 6 for c in cases))
        self.assertEqual(cases, suite.modbus_cases("inlet", 50, random.Random(42)))

    def test_thresholds_and_inlet_flow_oracle(self):
        self.assertEqual(suite.expected_commands(40.0), (25, 100))
        self.assertEqual(suite.expected_commands(70.0), (25, 100))
        self.assertEqual(suite.expected_commands(90.0), (75, 50))
        readings = {
            "device": {"result": "normal_response", "values": [6525, 25]},
            "inlet": {"result": "normal_response", "values": [100, 250]},
        }
        data, flags = suite.flatten_snapshot(readings)
        self.assertEqual(data["water_level_pct"], 65.25)
        self.assertEqual(flags, [])
        readings["inlet"]["values"] = [100, 0]
        _, flags = suite.flatten_snapshot(readings)
        self.assertIn("inlet_flow_inconsistent", flags)

    def test_hmi_api_discovery(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "services" / "hmi"
            directory.mkdir(parents=True)
            (directory / "app.py").write_text('route = "/api/state"\n', encoding="utf-8")
            self.assertEqual(suite.discover_hmi_paths(Path(tmp)), ["/api/state"])

    def test_hmi_http_status_and_json(self):
        server = HTTPServer(("127.0.0.1", 0), FakeHTTPHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with patch.object(suite, "HMI_PORT", server.server_address[1]):
            good = suite.read_hmi("/api/state")
            unknown = suite.read_hmi("/__missing__")
        server.shutdown()
        server.server_close()
        fields = suite.extract_json_fields(json.loads(good["body"]))
        self.assertEqual(good["http_status"], 200)
        self.assertEqual(unknown["http_status"], 404)
        self.assertEqual(fields["gate_actual_pct"], 25)

    def test_end_to_end_campaign_orchestration_offline(self):
        class FakeWorker:
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
            def request(self, operation, **kwargs):
                if operation == "snapshot":
                    return {"readings": {
                        "device": {"result": "normal_response", "values": [6525, 25]},
                        "inlet": {"result": "normal_response", "values": [100, 250]},
                    }}
                case = kwargs["case"]
                if case["function"] == 4 and case["address"] == 0 and case["quantity"] in (1, 2):
                    result, code = "normal_response", ""
                else:
                    result, code = "modbus_exception", 2
                return {"data": {"result": result, "exception_code": code,
                                  "latency_ms": 1.0, "request_hex": "00", "response_hex": "00"}}

        def fake_hmi(path):
            return {"http_status": 200 if path == "/" else 404, "latency_ms": 1.1,
                    "result": "http_response", "detail": "mock", "body": b"<html>OK</html>"}
        with tempfile.TemporaryDirectory() as tmp:
            args = argparse.Namespace(seed=42, per_node=18, delay=0.1, hmi_api_path=[],
                                      output_dir=tmp, enable_write_experiment=False)
            with patch.object(suite, "ModbusWorker", FakeWorker), \
                 patch.object(suite, "compose_running", lambda: set(suite.LAB_SERVICES)), \
                 patch.object(suite, "read_hmi", fake_hmi), \
                 patch.object(suite, "discover_hmi_paths", lambda _: []), \
                 patch.object(suite.time, "sleep", lambda _: None):
                result = suite.run_campaign(args)
            self.assertEqual(result, 0)
            csv_files = list(Path(tmp).glob("multinode_*.csv"))
            self.assertEqual(len(csv_files), 1)
            with csv_files[0].open(newline="") as f:
                records = list(csv.DictReader(f))
            self.assertEqual(len([r for r in records if r["phase"] == "fuzz" and r["target"] in ("device", "inlet")]), 36)
            self.assertTrue(list(Path(tmp).glob("*_summary.json")))


if __name__ == "__main__":
    unittest.main()
