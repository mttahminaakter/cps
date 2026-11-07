
import socket
import struct
import random
import time
import csv
import sys

HOST = "inlet"
PORT = 5020
EXPECTED_IP = "172.28.10.21"

# Safety: allow only the simulated inlet device.
if socket.gethostbyname(HOST) != EXPECTED_IP:
    sys.exit("Wrong target. Test stopped.")

random.seed(42)

# Traditional fuzzing: random values and boundary cases.
tests = [
    (0, 1), (0, 2), (1, 1),
    (0, 0), (0, 126), (100, 1)
]

for i in range(14):
    address = random.choice([0, 1, 2, 10, 100, 65535])
    quantity = random.choice([0, 1, 2, 3, 125, 126])
    tests.append((address, quantity))

writer = csv.writer(sys.stdout)
writer.writerow(["test", "address", "quantity", "result", "response_ms"])

for number, (address, quantity) in enumerate(tests, 1):
    # Modbus Function Code 04: Read Input Registers.
    request = struct.pack(
        "!HHHBBHH", number, 0, 6, 1, 4, address, quantity
    )

    start = time.monotonic()

    try:
        with socket.create_connection((HOST, PORT), timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(request)

            header = sock.recv(260)

        if len(header) >= 9:
            function = header[7]

            if function == 4:
                result = "normal_response"
            elif function == 0x84:
                result = "modbus_exception"
            else:
                result = "unexpected_response"
        else:
            result = "incomplete_response"

    except (OSError, ValueError):
        result = "connection_error"

    elapsed = round((time.monotonic() - start) * 1000, 2)

    writer.writerow([number, address, quantity, result, elapsed])
    sys.stdout.flush()

    time.sleep(0.3)

