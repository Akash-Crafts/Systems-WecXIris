import socket
import threading

HOST = "127.0.0.1"
PORT = 57545


def create_socket():
    print("Creating Server side socket.........")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_socket.bind((HOST, PORT))

    return server_socket


def accept_connection(server_socket):
    server_socket.listen(1)

    print(f"Server is listening on {HOST}:{PORT} ........")

    client_conn, client_addr = server_socket.accept()

    print(f"Connected to {client_addr[0]}:{client_addr[1]}")

    return client_conn


def receive_messages(client_conn, stop_event):
    while not stop_event.is_set():
        try:
            message = client_conn.recv(1024)

            if not message:
                print("\nConnection closed by client.")
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


def send_messages(client_conn, stop_event):
    while not stop_event.is_set():
        try:
            message = input()

            if message.lower() == "/quit":
                print("Closing connection...")
                stop_event.set()

                try:
                    client_conn.sendall(message.encode("utf-8"))
                    client_conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

                break

            client_conn.sendall(message.encode("utf-8"))

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

        print("\nChat started!")
        print("Type /quit to leave.\n")

        stop_event = threading.Event()

        receive_thread = threading.Thread(
            target=receive_messages, args=(client_conn, stop_event), daemon=True
        )

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
