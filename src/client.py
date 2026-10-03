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
    print("Creating Client side socket.........")

    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# Connect to Server
def connect_to_server(client_socket):
    client_socket.connect((HOST, PORT))

    print(f"Connected to {HOST}:{PORT}")


# Handshake
def establish_handshake(client_socket):
    print("Generating ECDH Keys.......")
    my_private_key = crypto.generate_private_key()
    my_public_key = crypto.generate_public_key(my_private_key)

    print("Sending DH public key......")
    send_frame(client_socket, FrameType.HANDSHAKE, crypto.serialize_key(my_public_key))

    print("Receiving server DH public key......")
    frame_type, peer_public_key_bytes = receive_frame(client_socket)
    peer_public_key = crypto.deserialize_key(peer_public_key_bytes)

    print("Shared secret derived.")
    shared_secret = crypto.derive_shared_secret(my_private_key, peer_public_key)

    print("Sending Salt.....")
    salt = crypto.generate_salt()
    send_frame(client_socket, FrameType.HANDSHAKE, salt)

    print("Generating Session_key....")
    session_key_c2s = crypto.derive_session_key(
        salt, shared_secret, info.client_to_server
    )
    session_key_s2c = crypto.derive_session_key(
        salt, shared_secret, info.server_to_client
    )

    print("Done.")
    return session_key_c2s, session_key_s2c


# Logic for Receiving Messages
def receive_messages(client_socket, stop_event):
    while not stop_event.is_set():
        try:
            frame = receive_frame(client_socket)

            if frame is None:
                print("\nConnection closed by server.")
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
def send_messages(client_socket, stop_event):
    while not stop_event.is_set():
        try:
            message = input()

            if message.lower() == "/quit":
                print("Closing connection...")
                stop_event.set()

                try:
                    send_frame(client_socket, FrameType.QUIT, message.encode("utf-8"))
                    client_socket.shutdown(
                        socket.SHUT_RDWR
                    )  # Stop Both RD(receiving) and WR(Sending).
                except OSError:
                    pass

                break

            send_frame(client_socket, FrameType.CHAT, message.encode("utf-8"))

        except (EOFError, KeyboardInterrupt):
            stop_event.set()

            try:
                client_socket.shutdown(socket.SHUT_RDWR)
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
    client_socket = create_socket()

    try:
        connect_to_server(client_socket)

        # Establish Same Secret Key
        shared_secret = establish_handshake(client_socket)

        print("\nChat started!")
        print("Type /quit to leave.\n")

        # Event for inter thread communication/Synchronization
        stop_event = threading.Event()

        # Receive thread for parallel execution of send(main thread) and receive
        receive_thread = threading.Thread(
            target=receive_messages, args=(client_socket, stop_event), daemon=True
        )  # daemon = True basically stops this thread if main thread is stopped

        receive_thread.start()

        send_messages(client_socket, stop_event)

        stop_event.set()

        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

        receive_thread.join(timeout=1)

    finally:
        client_socket.close()

        print("Connection closed.")


if __name__ == "__main__":
    main()
