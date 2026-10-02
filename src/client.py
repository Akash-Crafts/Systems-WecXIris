import socket
import threading

HOST = "127.0.0.1"
PORT = 57545


def create_socket():
    print("Creating Client side socket.........")

    return socket.socket(socket.AF_INET, socket.SOCK_STREAM)


def connect_to_server(client_socket):
    client_socket.connect((HOST, PORT))

    print(f"Connected to {HOST}:{PORT}")


def receive_messages(client_socket, stop_event):
    while not stop_event.is_set():
        try:
            message = client_socket.recv(1024)

            if not message:
                print("\nConnection closed by server.")
                stop_event.set()
                break

            message = message.decode("utf-8")

            if message.lower() == "/quit":
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


def send_messages(client_socket, stop_event):
    while not stop_event.is_set():
        try:
            message = input()

            if message.lower() == "/quit":
                print("Closing connection...")
                stop_event.set()

                try:
                    client_socket.sendall(message.encode("utf-8"))
                    client_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

                break

            client_socket.sendall(message.encode("utf-8"))

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

        stop_event = threading.Event()

        receive_thread = threading.Thread(
            target=receive_messages, args=(client_socket, stop_event), daemon=True
        )

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
