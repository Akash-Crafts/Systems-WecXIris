import socket
import threading
from framing import send_frame, receive_frame
import crypto
from protocol import FrameType, info
import struct
from cryptography.exceptions import InvalidTag

HOST = "127.0.0.1"
PORT = 57545


# Creating the Socket
def create_socket():
    print("Creating Server side socket.........")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))

    return server_socket


# Accepting the Connection from client
def accept_connection(server_socket):
    server_socket.listen(1)

    print(f"Server is listening on {HOST}:{PORT} ........")

    client_conn, client_addr = server_socket.accept()

    print(f"Connected to {client_addr[0]}:{client_addr[1]}")

    return client_conn


# Handshake
def establish_handshake(client_conn, stop_event):
    print("Generating ECDH Keys.......")
    my_private_key = crypto.generate_private_key()
    my_public_key = crypto.generate_public_key(my_private_key)

    print("Receiving client DH public key......")

    frame = receive_frame(client_conn)

    if frame is None:
        stop_event.set()
        return False, None, None

    frame_type, peer_public_key_bytes = frame

    if frame_type != FrameType.HANDSHAKE:
        stop_event.set()
        return False, None, None
    peer_public_key = crypto.deserialize_key(peer_public_key_bytes)

    print("Sending DH public key......")
    send_frame(client_conn, FrameType.HANDSHAKE, crypto.serialize_key(my_public_key))

    print("Shared secret derived.")
    shared_secret = crypto.derive_shared_secret(my_private_key, peer_public_key)

    frame = receive_frame(client_conn)

    if frame is None:
        stop_event.set()
        return False, None, None

    frame_type, salt = frame

    if frame_type != FrameType.HANDSHAKE or len(salt) != 32:
        stop_event.set()
        return False, None, None

    print("Salt Received.")

    S2C_ENC_KEY, C2S_ENC_KEY, S2C_MAC_KEY, C2S_MAC_KEY = crypto.derive_keys(
        salt, shared_secret
    )

    print("Confirming Valid HANDSHAKE.........")
    transcript = peer_public_key_bytes + crypto.serialize_key(my_public_key) + salt
    expected_mac_C2S = crypto.compute_hmac(C2S_MAC_KEY, transcript)

    frame = receive_frame(client_conn)

    if frame is None:
        stop_event.set()
        return False, None, None

    frame_type, received_hmac_C2S = frame

    if frame_type == FrameType.HANDSHAKE_CONFIRM and crypto.compare_hmac(
        received_hmac_C2S, expected_mac_C2S
    ):
        computed_hmac_S2C = crypto.compute_hmac(S2C_MAC_KEY, transcript)
        send_frame(client_conn, FrameType.HANDSHAKE_CONFIRM, computed_hmac_S2C)

        print("Client MAC keys  confirmed.")

    else:
        print("Error in confirming valid Handshake...")
        print("Aborting Connection.....")
        send_frame(client_conn, FrameType.QUIT, b"/quit")
        stop_event.set()

    return not stop_event.is_set(), S2C_ENC_KEY, C2S_ENC_KEY


# Logic for Receiving Messages
def receive_messages(client_conn, Key, stop_event):
    expected_recv_seq = 0
    while not stop_event.is_set():
        try:
            frame = receive_frame(client_conn)

            if frame is None:
                print("\nConnection closed by client.")
                stop_event.set()
                break

            frame_type, received_payload = frame

            # received_payload = Seq_No || Nonce || Cipher_text || Auth Tag

            if frame_type == FrameType.CHAT:
                # 8(sequence no) + 12(Nonce) + 16(Auth tag)
                if len(received_payload) < 8 + 12 + 16:
                    print("Invalid encrypted message")
                    print("Aborting Connection.....")
                    stop_event.set()
                    break

                received_seq = struct.unpack("!Q", received_payload[:8])[0]

                # Replay attack found since expected seq and received seq doesnt match
                if received_seq != expected_recv_seq:
                    print("Replay or reordered message detected")
                    print("Aborting Connection.....")
                    stop_event.set()
                    break

                try:
                    # aad = Type + received_seq
                    aad = struct.pack("!BQ", int(FrameType.CHAT), received_seq)
                    plain_text = crypto.decrypt_message(Key, received_payload[8:], aad)
                except InvalidTag:
                    # Something was modified
                    print("Message authentication Failed")
                    print("Aborting Connection....")
                    stop_event.set()
                    break
                except ValueError as e:
                    print(f"Invalid payload: {e}")
                    print("Aborting Connection....")
                    stop_event.set()
                    break

                print(f"Friend: {plain_text.decode('utf-8')}")

                # SEQ_No++ for next msg
                expected_recv_seq += 1
            elif frame_type == FrameType.QUIT:
                print("\nFriend left the chat.")
                stop_event.set()
                break

        except (ConnectionResetError, BrokenPipeError, OSError):
            stop_event.set()
            break

        except Exception as e:
            print(f"\nAn error occurred while receiving: {e}")
            stop_event.set()
            break


# Logic for Sending messages
def send_messages(client_conn, Key, stop_event):
    send_seq = 0
    while not stop_event.is_set():
        try:
            message = input()

            if message.lower() == "/quit":
                print("Closing connection...")
                stop_event.set()

                try:
                    send_frame(client_conn, FrameType.QUIT, message.encode("utf-8"))
                    client_conn.shutdown(
                        socket.SHUT_RDWR
                    )  # Stop Both RD(receiving) and WR(Sending).
                except OSError:
                    pass

                break

            plain_text = message.encode("utf-8")
            # data that needs to be authenticated but not encrypted
            aad = struct.pack("!BQ", int(FrameType.CHAT), send_seq)
            # encrypted_msg = nonce + cipherText + auth tag
            encrypted_msg = crypto.encrypt_message(Key, plain_text, aad)
            # total payload = sequence_no(to prevent replay attacks) + nonce + cipherText + auth tag
            payload = struct.pack("!Q", send_seq) + encrypted_msg
            send_frame(client_conn, FrameType.CHAT, payload)

            send_seq += 1
        # handle Ctrl  + C and EOF error
        except (EOFError, KeyboardInterrupt):
            stop_event.set()

            try:
                client_conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

            break

        except (ConnectionResetError, BrokenPipeError, OSError):
            stop_event.set()
            break

        except Exception as e:
            print(f"An error occurred while sending: {e}")
            stop_event.set()
            break


def main():
    server_socket = create_socket()
    client_conn = None

    try:
        client_conn = accept_connection(server_socket)

        # Event for inter thread communication/Synchronization
        stop_event = threading.Event()

        # Establish Same Secret Key
        try:
            status, S2C_enc_key, C2S_enc_key = establish_handshake(
                client_conn, stop_event
            )
        except:
            print("Error in confirming valid Handshake...")
            print("Aborting Connection.....")
            stop_event.set()
            status = False

        if not status:
            return

        print("\nChat started!")
        print("Type /quit to leave.\n")

        # Receive thread for parallel execution of send(main thread) and receive
        receive_thread = threading.Thread(
            target=receive_messages,
            args=(client_conn, C2S_enc_key, stop_event),
            daemon=True,
        )  # daemon = True basically stops this thread if main thread is stopped

        receive_thread.start()

        send_messages(client_conn, S2C_enc_key, stop_event)

        stop_event.set()

        try:
            client_conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        receive_thread.join(timeout=1)

    finally:
        if client_conn is not None:
            client_conn.close()

        server_socket.close()

        print("Connection closed.")


if __name__ == "__main__":
    main()
