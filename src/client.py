import socket
import threading
from framing import send_frame, receive_frame

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
def receive_messages(client_socket, stop_event):
    while not stop_event.is_set():
        try:
            frame = receive_frame(client_socket)

            if frame is None:
                print("\nConnection closed by server.")
                stop_event.set()
                break

            frame_type, message = frame
            if frame_type == 2:
                print("\nFriend left the chat.")
                stop_event.set()
                break

            print(f"Friend: {message}")

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
                    send_frame(client_socket, message)
                    client_socket.shutdown(
                        socket.SHUT_RDWR
                    )  # Stop Both RD(receiving) and WR(Sending).
                except OSError:
                    pass

                break

            send_frame(client_socket, message)

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
