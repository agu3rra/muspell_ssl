import socket
import ssl
import select

IP = "127.0.0.1"
PORT = 8447
BUFFER = 4096

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_address = (IP, PORT)
server_socket.bind(server_address)
server_socket.listen()

# This will handle multiple client (aka sockets)
sockets_list = [server_socket]
clients = {}


def receive_message(client_socket):
    try:
        message = client_socket.recv(BUFFER)
        if not len(message):
            return False
        return {"data": message}

    except:
        return False


while True:
    read_sockets, _, exception_sockets = select.select(sockets_list,
                                                       [],
                                                       sockets_list)
    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            client_socket, client_address = server_address.accept()
            message = receive_message(client_socket)
            if message is False:
                continue
            sockets_list.append(client_socket)
            clients[client_socket] = message
            print("Accepted new connection from {}:{} username:{}".format(
                client_address[0],
                client_address[1],
                message["data"].decode("utf-8")
            ))
        else:
            message = receive_message(notified_socket)
            if message is False:
                print("Closed connection.")
                sockets_list.remove(notified_socket)
                del clients[notified_socket]
                continue

            message = clients[notified_socket]
            print("Received message:\n{}".format(message.decode("utf-8")))

            for client_socket in clients:
                if client_socket != notified_socket:
                    client_socket.send()


context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.set_ciphers("AES256")
context.load_cert_chain(
    certfile="certificate.pem",
    keyfile="key.pem")

bindsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bindsocket.bind(('', 8447))
bindsocket.listen(5)  # 5 simultaneous connections

while True:
    newsocket, fromaddr = bindsocket.accept()
    sslsoc = context.wrap_socket(newsocket, server_side=True)
    request = sslsoc.read()
    print(request)
