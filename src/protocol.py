from enum import IntEnum


class FrameType(IntEnum):
    CHAT = 1
    HANDSHAKE = 2
    HANDSHAKE_CONFIRM = 3
    QUIT = 4


class info:
    client_to_server_encr = b"client-to-server"
    server_to_client_encr = b"server-to-client"
    client_to_server_mac = b"client_to_server_mac"
    server_to_client_mac = b"server_to_client_mac"
