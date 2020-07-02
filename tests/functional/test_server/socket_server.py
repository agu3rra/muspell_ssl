import socket
import ssl

IP = "127.0.0.1"
PORT = 8447
BUFFER = 4096
SIM_CONNECTIONS = 5

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
# context.set_ciphers("AES256")
context.load_cert_chain(
    certfile="certificate.pem",
    keyfile="key.pem")

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server_address = (IP, PORT)
server_socket.bind(server_address)
server_socket.listen(SIM_CONNECTIONS)

print("Server is listening on port {}...".format(PORT))
while True:
    try:
        newsocket, fromaddr = server_socket.accept()
        sslsoc = context.wrap_socket(newsocket, server_side=True)
        request = sslsoc.read()
        print("Incoming request:")
        print(request)
    except Exception as e:
        print("Exception detected:")
        print(str(e))
