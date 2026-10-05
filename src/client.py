import socket
import threading
from framing import send_frame, receive_frame
from protocol import FrameType
from handshake import HandshakeError, perform_client_handshake
from session import send_chat_message, receive_chat_message

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


# Logic for Receiving Messages
def receive_messages(client_socket, key, stop_event):
    expected_recv_seq = 0  # to track for replay attacks
    while not stop_event.is_set():
        try:
            message, expected_recv_seq = receive_chat_message(
                client_socket, key, expected_recv_seq
            )

            if message is None:
                print("\nConnection closed by server.")
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
def send_messages(client_socket, key, stop_event):
    send_sequence = 0
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

            send_chat_message(client_socket, key, message, send_sequence)
            send_sequence += 1

        # handle Ctrl  + C and EOF error
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


def main():
    client_socket = create_socket()

    try:
        connect_to_server(client_socket)

        # Event for inter thread communication/Synchronization
        stop_event = threading.Event()

        # Establish Same Secret Key
        print("Starting secure handshake...")
        try:
            session_keys = perform_client_handshake(client_socket)
        except HandshakeError as e:
            print(f"Handshake failed: {e}")
            print("Aborting Connection....")
            client_socket.close()
            return

        print("\nHandshake successful.")
        print("\nChat started!")
        print("Type /quit to leave.\n")

        # Receive thread for parallel execution of send(main thread) and receive
        receive_thread = threading.Thread(
            target=receive_messages,
            args=(client_socket, session_keys.receive_encryption_key, stop_event),
            daemon=True,
        )  # daemon = True basically stops this thread if main thread is stopped

        receive_thread.start()

        send_messages(client_socket, session_keys.send_encryption_key, stop_event)

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
