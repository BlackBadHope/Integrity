"""stdio <-> private Unix socket relay used as the profile's upstream command."""
import os
import socket
import sys
import threading

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.connect(sys.argv[1])


def upward():
    while True:
        data = os.read(0, 65536)
        if not data:
            sock.shutdown(socket.SHUT_WR)
            return
        sock.sendall(data)


threading.Thread(target=upward, daemon=True).start()
while True:
    data = sock.recv(65536)
    if not data:
        break
    os.write(1, data)
