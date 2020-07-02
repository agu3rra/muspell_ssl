import http.server
import ssl

# A simple test server
address = ("127.0.0.1", 8443)
server = http.server.HTTPServer(address, http.server.SimpleHTTPRequestHandler)
server.socket = ssl.wrap_socket(
    server.socket,
    server_side=True,
    certfile="certificate.pem",
    keyfile="key.pem",
    ssl_version=ssl.PROTOCOL_TLSv1
)

print("Hello! Server is up for testing. Fire away!")
server.serve_forever()
