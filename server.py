import socket
import threading
from utils import *

users = {}
""" users file structure:
users = {
    "username": {
        "password": "...",
        "blocked": [
            "...",
        ]
    }
}
"""
keys = {}
connections = []
total_connections = 0

class Client(threading.Thread):
    """ Client is a thread waiting for incoming messages to its socket. """

    def __init__(self, socket, address, signal):
        """ Instantiates a new Client object. """
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.username = None
        self.publicKey = None
        self.signal = signal

    def close(self):
        """ Closes the connection. """
        self.signal = False
        connections.remove(self)
        self.socket.close()
        print("Client from " + str(self.address) + " has disconnected")

    def register(self, username, password):
        """ Registers a new user and stores its password. Sends error if there is already a user with that username. """
        if username in users:
            sendPackets(self.socket, b"$register exists")
            return
        users[username] = {}
        users[username]["password"] = password
        users[username]["blocked"] = []
        self.username = username
        writeJSONFile("users", users)
        sendPackets(self.socket, b"$register success")
        print("@" + username + " registered and logged in successfully.")

    def login(self, username, password):
        """ Logs a user in. Sends error if there is no user with that username. If there is an open connection which logged in to that account, logs it out. """
        if username not in users:
            sendPackets(self.socket, b"$login nouser")
            return
        passw = users[username]["password"]
        if passw != password:
            sendPackets(self.socket, b"$login wrongpass")
            return
        prevSession = getConnection(username)
        if prevSession is not None:
            prevSession.logout(True)
        self.username = username
        sendPackets(self.socket, b"$login success")
        print("@" + username + " logged in successfully.")

    def logout(self, isForced):
        """ Logs a user out. Sends logout message to the client. """
        if isForced:
            sendPackets(self.socket, encrypt(self.publicKey, b"$logout forced"))
        else:
            sendPackets(self.socket, encrypt(self.publicKey, b"$logout"))
        print("@" + self.username + " logged out successfully.")
        self.username = None
        self.publicKey = None

    def block(self, username):
        """ Blocks a user. """
        if username not in users:
            sendPackets(self.socket, encrypt(self.publicKey, b"$block nouser"))
            return
        if username in users[self.username]["blocked"]:
            sendPackets(self.socket, encrypt(self.publicKey, b"$block already"))
            return
        users[self.username]["blocked"].append(username)
        writeJSONFile("users", users)
        sendPackets(self.socket, encrypt(self.publicKey, b"$block success"))

    def unblock(self, username):
        """ Unblocks a user. """
        if username not in users:
            print(username)
            print(users)
            sendPackets(self.socket, encrypt(self.publicKey, b"$unblock nouser"))
            return
        if username not in users[self.username]["blocked"]:
            sendPackets(self.socket, encrypt(self.publicKey, b"$unblock already"))
            return
        users[self.username]["blocked"].remove(username)
        writeJSONFile("users", users)
        sendPackets(self.socket, encrypt(self.publicKey, b"$unblock success"))

    def canSend(self, username):
        client = getConnection(username)
        if client is None:
            if username in users:
                sendPackets(self.socket, encrypt(self.publicKey, b"$user-offline"))
            else:
                sendPackets(self.socket, encrypt(self.publicKey, b"$user-notfound"))
        else:
            if self.username in users[username]["blocked"]:
                sendPackets(self.socket, encrypt(self.publicKey, b"$user-blocked"))
            elif client.publicKey is None:
                sendPackets(self.socket, encrypt(self.publicKey, b"$user-notsecure"))
            else:
                return client
        return False

    def run(self):
        """ Waits for incoming messages and processes them. """
        while self.signal:
            try:
                data = receivePackets(self.socket)
            except:
                if self.signal:
                    print("Client from " + str(self.address) + " has disconnected")
                    self.signal = False
                    connections.remove(self)
                break
            data = decrypt(keys["private"], data)
            if data.startswith(b"$close"):
                self.close()
            elif self.username is None:
                if data.startswith(b"$login"):
                    data = data.decode().split(" ", 2)
                    response = self.login(data[1], data[2])
                elif data.startswith(b"$register"):
                    data = data.decode().split(" ", 2)
                    response = self.register(data[1], data[2])
            elif self.publicKey is None:
                if data.startswith(b"$client-public-key"):
                    self.publicKey = data[19:].decode()
            else:
                if data.startswith(b"$logout"):
                    self.logout(False)
                elif data.startswith(b"$client-public-key"):
                    self.publicKey = data[19:].decode()
                elif data.startswith(b"$block"):
                    self.block(data[7:].decode())
                elif data.startswith(b"$unblock"):
                    self.unblock(data[9:].decode())
                elif data.startswith(b"$request-public-key"):
                    username = data[20:].decode()
                    client = self.canSend(username)
                    if client:
                        sendPackets(self.socket, encrypt(self.publicKey, str.encode("$user-public-key " + client.username + " " + client.publicKey)))                            
                elif data.startswith(b"$sending-to"):
                    data = data.split(b" ", 2)
                    username = data[1].decode()
                    message = data[2]
                    client = self.canSend(username)
                    if client:
                        sendPackets(client.socket, encrypt(client.publicKey, b"$coming-from " + str.encode(self.username) + b" " + message))
                elif data.startswith(b"$send-file-to"):
                    data = data.decode().split(" ", 2)
                    username = data[1]
                    fileName = data[2]
                    client = self.canSend(username)
                    if client:
                        sendPackets(client.socket, encrypt(client.publicKey, b"$file-perm " + str.encode(self.username) + b" " + str.encode(fileName)))
                elif data.startswith(b"$file-perm-ok"):
                    username = data[14:].decode()
                    client = self.canSend(username)
                    if client:
                        sendPackets(client.socket, encrypt(client.publicKey, b"$send-file-for " + str.encode(self.username) + b" " + str.encode(self.publicKey)))
                elif data.startswith(b"$file-perm-no"):
                    username = data[14:].decode()
                    client = self.canSend(username)
                    if client:
                        sendPackets(client.socket, encrypt(client.publicKey, b"$send-file-no "))
                elif data.startswith(b"$file-sending-to"):
                    data = data.split(b" ", 2)
                    username = data[1].decode()
                    client = self.canSend(username)
                    if client:
                        sendPackets(client.socket, encrypt(client.publicKey, b"$file-coming-from " + str.encode(self.username) + b" " + data[2]))

def newConnections(socket):
    """ Waits for new client connections and establishes server-client connection. """
    global keys, users, connections, total_connections
    print("Waiting for client connections...")
    while True:
        sock, address = socket.accept()
        sendPackets(sock, str.encode("$server-public-key " + keys["public"]))
        connections.append(Client(sock, address, True))
        connections[len(connections) - 1].start()
        print("New connection from " + str(address[1]))

def getConnection(username):
    """ Returns the Client object with the given username. """
    global connections
    for client in connections:
        if client.username == username:
            return client
    return None

if __name__ == "__main__":
    users = readJSONFile("users")
    if users is None:
        users = {}
    keys = readJSONFile("crypto-server")
    if keys is None:
        keys = generateKeys()
        writeJSONFile("crypto-server", keys)

    print("Welcome to SecureChat server.")
    host = input("Host: ")
    port = int(input("Port: "))

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((host, port))
    sock.listen(5)

    newConnectionsThread = threading.Thread(target=newConnections, args=(sock,))
    newConnectionsThread.start()