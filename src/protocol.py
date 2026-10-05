# protocol constants

from enum import IntEnum


class FrameType(IntEnum):
    HANDSHAKE = 1
    HANDSHAKE_CONFIRM = 2
    CHAT = 3
    QUIT = 4


class Size:
    FRAME_HEADER_SIZE = 5
    SEQUENCE_NUMBER_SIZE = 8
    SALT_SIZE = 32
    NONCE_SIZE = 12
    AUTH_TAG_SIZE = 16


class info:
    client_to_server_encr = b"client-to-server"
    server_to_client_encr = b"server-to-client"
    client_to_server_mac = b"client_to_server_mac"
    server_to_client_mac = b"server_to_client_mac"
