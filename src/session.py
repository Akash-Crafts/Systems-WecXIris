# Encrypted chat messages

import struct
from cryptography.exceptions import InvalidTag

from crypto import decrypt_message, encrypt_message
from framing import send_frame, receive_frame
from protocol import Size, FrameType, info


# Message sending logic
# Encrypt and send one Chat message
def send_chat_message(sock, key, msg, seqNo):
    # String to Bytes
    plaintext = msg.encode("utf-8")

    # Additional Authenticated Data(AAD) Data that needs to be authenticated but not encrypted
    aad = struct.pack("!BQ", int(FrameType.CHAT), seqNo)

    # encrypted_msg = Nonce || CipherText || Auth tag
    encrypted_msg = encrypt_message(key, plaintext, aad)

    # Final payload = Sequence No || Nonce || CipherText || Auth Tag
    payload = struct.pack("!Q", seqNo) + encrypted_msg

    send_frame(sock, FrameType.CHAT, payload)


# Message receiving logic
# Receive, Validate and Decrypt one Chat message
def receive_chat_message(sock, key, expected_seqNo):

    frame = receive_frame(sock)

    if frame is None:
        return None, expected_seqNo

    frame_type, payload = frame

    if frame_type == FrameType.QUIT:
        return "/quit", expected_seqNo

    if frame_type != FrameType.CHAT:
        raise ValueError("Unexpected Frame Type")

    # payload = Sequence No || Nonce || CipherText || Auth Tag

    received_seqNo = struct.unpack("!Q", payload[: Size.SEQUENCE_NUMBER_SIZE])[0]

    if received_seqNo != expected_seqNo:
        # Replay Attack Found
        raise ValueError("Replay Message Detected.")

    aad = struct.pack("!BQ", int(FrameType.CHAT), expected_seqNo)

    try:
        plaintext = decrypt_message(key, payload[Size.SEQUENCE_NUMBER_SIZE :], aad)

    except InvalidTag:
        # Auth tags didnt match ---> Something was tampered
        raise ValueError("Authentication Failed.")

    # Expected Seq No += 1
    return plaintext.decode("utf-8"), expected_seqNo + 1
