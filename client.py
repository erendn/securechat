import socket
import threading
import sys
from utils import *

serverKey = None
keys = {}
keyShared = False
toSend = None

def receive(socket, signal):
    """ Waits for incoming messages and processes them. """
    global serverKey, keys, keyShared, toSend
    while signal:
        data = receivePackets(socket)
        if keyShared is True:
            data = decrypt(keys["private"], data)
        if data.startswith(b"$server-public-key"):
            serverKey = data.decode()[19:]
        elif data.startswith(b"$request-public-key"):
            sendPackets(socket, encrypt(serverKey, str.encode("$client-public-key " + keys["public"])))
            keyShared = True
        elif data.startswith(b"$coming-from"):
            print("@" + data.split(b" ", 2)[1].decode() + ":")
            print(decrypt(keys["private"], data.split(b" ", 2)[2]).decode())
        elif data.startswith(b"$user-public-key"):
            publicKey = data[17:].decode()
            sendPackets(sock, encrypt(serverKey, str.encode("$sending-to " + username + " ") + encrypt(publicKey, str.encode(message))))
        else:
            print(str(data.decode()))

if __name__ == "__main__":
    keys = readFile("crypto-client")
    if keys is None:
        keys = generateKeys()
        writeFile("crypto-client", keys)
    host = input("Host: ")
    port = int(input("Port: "))

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((host, port))
    except:
        print("Could not make a connection to the server")
        input("Press enter to quit")
        sys.exit(0)

    receiveThread = threading.Thread(target=receive, args=(sock, True))
    receiveThread.start()

    while True:
        message = input()
        if message.startswith("@"):
            # split must change
            username = message.split(" ", 1)[0][1:]
            message = message.split(" ", 1)[1]
            sendPackets(sock, encrypt(serverKey, str.encode("$request-public-key " + username)))
            toSend = message
        else:
            sendPackets(sock, str.encode(message))