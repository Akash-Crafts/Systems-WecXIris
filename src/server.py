# ECDH + key confirmation

import socket
import threading
from framing import send_frame, receive_frame
from protocol import FrameType
from handshake import HandshakeError, perform_server_handshake
from session import send_chat_message, receive_chat_message

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


# Logic for Receiving Messages
def receive_messages(client_conn, key, stop_event):
    expected_recv_seq = 0  # to track for replay attacks
    while not stop_event.is_set():
        try:
            message, expected_recv_seq = receive_chat_message(
                client_conn, key, expected_recv_seq
            )

            if message is None:
                print("\nConnection closed by client.")
                stop_event.set()
                break

            if message == "/quit":
                print("\nFriend left the chat.")
                stop_event.set()
                break

            print(f"Friend: {message}")

        # Catching the Defined Protocol Errors
        except ValueError as e:
            print(f"Protocol Error : {e}")
            print("Aborting Connection....")
            stop_event.set()
            break

        except (ConnectionResetError, BrokenPipeError, OSError):
            stop_event.set()
            break


# Logic for Sending messages
def send_messages(client_conn, key, stop_event):
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

            send_chat_message(client_conn, key, message, send_seq)
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


def main():
    server_socket = create_socket()
    client_conn = None

    try:
        client_conn = accept_connection(server_socket)

        # Event for inter thread communication/Synchronization
        stop_event = threading.Event()

        # Establish Same Secret Key
        print("Starting secure handshake...")
        try:
            session_keys = perform_server_handshake(client_conn)
        except HandshakeError as e:
            print(f"Handshake failed: {e}")
            print("Aborting Connection.....")
            client_conn.close()
            server_socket.close()
            return

        print("\nHandshake successful.")
        print("\nChat started!")
        print("Type /quit to leave.\n")

        # Receive thread for parallel execution of send(main thread) and receive
        receive_thread = threading.Thread(
            target=receive_messages,
            args=(client_conn, session_keys.receive_encryption_key, stop_event),
            daemon=True,
        )  # daemon = True basically stops this thread if main thread is stopped

        receive_thread.start()

        send_messages(client_conn, session_keys.send_encryption_key, stop_event)

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
