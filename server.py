import socket
import threading
from utils import *


users = {}
keys = {}
connections = []
total_connections = 0
buffer = 2048


class Client(threading.Thread):
    def __init__(self, socket, address, username, publicKey, signal):
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.username = username
        self.publicKey = publicKey
        self.signal = signal

    def run(self):
        global buffer
        while self.signal:
            try:
                data = self.socket.recv(buffer)
            except:
                print("Client " + str(self.username) + " has disconnected")
                self.signal = False
                connections.remove(self)
                break
            data = decrypt(keys["private"], data)
            if data.startswith(b"$request-public-key"):
                username = data[20:].decode()
                client = getConnection(username)
                if client is None:
                    self.socket.sendall(
                        encrypt(
                            self.publicKey,
                            str.encode(
                                "There is no user with the given username: " +
                                username)))
                else:
                    self.socket.sendall(
                        encrypt(
                            self.publicKey,
                            str.encode("$user-public-key " +
                                       client.publicKey)))
            elif data.startswith(b"$sending-to"):
                username = data.split(b" ", 2)[1].decode()
                message = data.split(b" ", 2)[2]
                client = getConnection(username)
                client.socket.sendall(
                    encrypt(
                        client.publicKey,
                        str.encode("$coming-from " + self.username + " ") +
                        message))


def send(socket, message):
    socket.sendall(str.encode(message))


def newConnections(socket):
    global keys, users, buffer, connections, total_connections
    while True:
        sock, address = socket.accept()
        username = getUsername(address)
        if username is None:
            sock.sendall(
                str.encode(
                    "A username for your IP address is not recorded. Please provide a username: "
                ))
            try:
                username = sock.recv(buffer).decode("utf-8")
                while getAddress(username) is not None:
                    sock.sendall(
                        str.encode(
                            "Username already exists. Please provide a different username: "
                        ))
                    username = sock.recv(buffer).decode("utf-8")
            except:
                return
        users[username] = address
        writeFile("users", users)
        send(sock, "$server-public-key " + keys["public"])
        send(sock, "$request-public-key")
        publicKey = sock.recv(buffer)
        publicKey = decrypt(keys["private"], publicKey).decode()
        if publicKey.startswith("$client-public-key"):
            publicKey = publicKey[19:]
        connections.append(Client(sock, address, username, publicKey, True))
        connections[len(connections) - 1].start()
        print("New connection with user @" + username + " from " +
              str(address[1]))
        total_connections += 1


def getConnection(username):
    global connections
    for client in connections:
        if client.username == username:
            return client
    return None


def getUsername(address):
    global users
    for user, ip in users.items():
        if ip == address:
            return user
    return None


def getAddress(username):
    global users
    for user, ip in users.items():
        if user == username:
            return ip
    return None


if __name__ == "__main__":
    users = readFile("users")
    if users is None:
        users = {}
    keys = readFile("crypto-server")
    if keys is None:
        keys = generateKeys()
        writeFile("crypto-server", keys)

    host = input("Host: ")
    port = int(input("Port: "))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)

    newConnectionsThread = threading.Thread(target=newConnections,
                                            args=(sock, ))
    newConnectionsThread.start()
