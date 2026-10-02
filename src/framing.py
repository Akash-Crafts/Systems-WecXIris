import socket
import struct


def send_frame(sock, payload):
    if payload.lower() == "/quit":
        frame_type = 2  # indication to quit
    else:
        frame_type = 1  # normal chat message

    payload_bytes = payload.encode("utf-8")
    length = len(payload_bytes)  # length of the message in bytes

    header = struct.pack(
        "!BI", frame_type, length
    )  # header = [TYPE - 1 byte ][LENGTH - 4 bytes]

    frame = header + payload_bytes  # frame = [TYPE][LENGTH][PAYLOAD]

    sock.sendall(frame)


# logic for receiving exactly n bytes
def recv_exact(sock, n):
    data = b""

    while len(data) < n:
        chunk = sock.recv(n - len(data))
        # means connection is closed before data is reached here
        if not chunk:
            return None
        data += chunk

    return data


# logic for receiving the full payload
def receive_frame(sock):
    header = recv_exact(sock, 5)  # know the header from the first 5 bytes

    if header is None:
        return None

    frame_type, length = struct.unpack(
        "!BI", header
    )  # unpack byte info to int frame_type, Length

    payload_bytes = recv_exact(sock, length)  # length bytes of actual data

    if payload_bytes is None:
        return None

    payload = payload_bytes.decode("utf-8")

    return frame_type, payload
