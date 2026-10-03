import socket
import threading
from framing import send_frame, receive_frame
import crypto

from enum import IntEnum


class FrameType(IntEnum):
    CHAT = 1
    HANDSHAKE = 2
    QUIT = 3


class info:
    client_to_server = b"client-to-server"
    server_to_client = b"server-to-client"


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
def establish_handshake(client_conn):
    print("Generating ECDH Keys.......")
    my_private_key = crypto.generate_private_key()
    my_public_key = crypto.generate_public_key(my_private_key)

    print("Receiving client DH public key......")
    frame_type, peer_public_key_bytes = receive_frame(client_conn)
    peer_public_key = crypto.deserialize_key(peer_public_key_bytes)

    print("Sending DH public key......")
    send_frame(client_conn, FrameType.HANDSHAKE, crypto.serialize_key(my_public_key))

    print("Shared secret derived.")
    shared_secret = crypto.derive_shared_secret(my_private_key, peer_public_key)

    frame_type, salt = receive_frame(client_conn)
    print("Salt Received.")

    print("Generating Session_key....")
    session_key_s2c = crypto.derive_session_key(
        salt, shared_secret, info.server_to_client
    )
    session_key_c2s = crypto.derive_session_key(
        salt, shared_secret, info.client_to_server
    )

    print("Done.")
    return session_key_c2s, session_key_s2c


# Logic for Receiving Messages
def receive_messages(client_conn, stop_event):
    while not stop_event.is_set():
        try:
            frame = receive_frame(client_conn)

            if frame is None:
                print("\nConnection closed by client.")
                stop_event.set()
                break

            frame_type, message = frame

            if frame_type == FrameType.QUIT:
                print("\nFriend left the chat.")
                stop_event.set()
                break

            print(f"Friend: {message.decode('utf-8')}")

        except (ConnectionResetError, BrokenPipeError, OSError):
            stop_event.set()
            break

        except Exception as e:
            print(f"\nAn error occurred while receiving: {e}")
            stop_event.set()
            break


# Logic for Sending messages
def send_messages(client_conn, stop_event):
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

            send_frame(client_conn, FrameType.CHAT, message.encode("utf-8"))

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

        # Establish Same Secret Key
        shared_secret = establish_handshake(client_conn)

        print("\nChat started!")
        print("Type /quit to leave.\n")

        # Event for inter thread communication/Synchronization
        stop_event = threading.Event()

        # Receive thread for parallel execution of send(main thread) and receive
        receive_thread = threading.Thread(
            target=receive_messages, args=(client_conn, stop_event), daemon=True
        )  # daemon = True basically stops this thread if main thread is stopped

        receive_thread.start()

        send_messages(client_conn, stop_event)

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
