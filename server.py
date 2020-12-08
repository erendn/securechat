import socket
import threading
from utils import *

users = {}
keys = {}
connections = []
total_connections = 0
buffer = 2048

class Client(threading.Thread):
    """ Client is a thread waiting for incoming messages to its socket. """

    def __init__(self, socket, address, username, publicKey, signal):
        """ Instantiates a new Client object. """
        threading.Thread.__init__(self)
        self.socket = socket
        self.address = address
        self.username = username
        self.publicKey = publicKey
        self.signal = signal

    def run(self):
        """ Waits for incoming messages and processes them. """
        global buffer
        while self.signal:
            try:
                data = receivePackets(self.socket)
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
                    sendPackets(self.socket, encrypt(self.publicKey, str.encode("There is no user with the given username: " + username)))
                else:
                    sendPackets(self.socket, encrypt(self.publicKey, str.encode("$user-public-key " + client.publicKey)))
            elif data.startswith(b"$sending-to"):
                username = data.split(b" ", 2)[1].decode()
                message = data.split(b" ", 2)[2]
                client = getConnection(username)
                sendPackets(client.socket, encrypt(client.publicKey, str.encode("$coming-from " + self.username + " ") + message))

def newConnections(socket):
    """ Waits for new client connections and establishes server-client connection. """
    global keys, users, buffer, connections, total_connections
    while True:
        sock, address = socket.accept()
        username = getUsername(address)
        if username is None:
            sendPackets(sock, str.encode("A username for your IP address is not recorded. Please provide a username: "))
            try:
                username = receivePackets(sock).decode("utf-8")
                while getAddress(username) is not None:
                    sendPackets(sock, str.encode("Username already exists. Please provide a different username: "))
                    username = receivePackets(sock).decode("utf-8")
            except:
                return
        users[username] = address
        writeFile("users", users)
        sendPackets(sock, str.encode("$server-public-key " + keys["public"]))
        sendPackets(sock, str.encode("$request-public-key"))
        publicKey = receivePackets(sock)
        publicKey = decrypt(keys["private"], publicKey).decode()
        if publicKey.startswith("$client-public-key"):
            publicKey = publicKey[19:]
        connections.append(Client(sock, address, username, publicKey, True))
        connections[len(connections) - 1].start()
        print("New connection with user @" + username + " from " +
              str(address[1]))
        total_connections += 1

def getConnection(username):
    """ Returns the Client object with the given username. """
    global connections
    for client in connections:
        if client.username == username:
            return client
    return None

def getUsername(address):
    """ Returns the username of the client with the given IP address. """
    global users
    for user, ip in users.items():
        if ip == address:
            return user
    return None

def getAddress(username):
    """ Returns the IP address of the client with the given name. """
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

    newConnectionsThread = threading.Thread(target=newConnections, args=(sock,))
    newConnectionsThread.start()