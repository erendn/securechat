import os
import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util import number

def readFile(path):
    """ Reads a file from the given path and returns data in byte array format. Returns None if file does not exist."""
    try:
        file = open(path, mode="rb")
        content = file.read()
        file.close()
        return content
    except:
        return None

def writeFile(path, content, parentFolder="downloads"):
    """ Writes the content in a file on the given path. If path does not exist, makes a new directory. """
    path = os.path.join(parentFolder, path)
    if not os.path.exists(path.rsplit("\\", 1)[0]):
        os.mkdir(path.rsplit("\\", 1)[0])
    origPath = path.rsplit(".")
    count = 1
    while os.path.exists(path):
        path = origPath[0] + "(" + str(count) + ")." + origPath[1]
        count += 1
    file = open(path, mode="wb")
    file.write(content)
    file.close()

def readJSONFile(path):
    """ Reads a JSON file from the given path. Returns None if file does not exist."""
    try:
        file = open(path + ".json", "r")
        data = json.loads(file.read())
        file.close()
        return data
    except:
        return None

def writeJSONFile(path, content):
    """ Writes a JSON file to the given path with the given content. """
    with open(path + ".json", "w") as file:
        json.dump(content, file)
        file.close()

def generateKeys(bitSize=2048):
    """ Returns a dict with randomly generated RSA key string pair with the given bit size. """
    private = RSA.generate(2048)
    public = private.publickey()
    keys = {}
    keys["private"] = private.export_key().decode()
    keys["public"] = public.export_key().decode()
    return keys

def encrypt(key, message):
    """ Encrypts the given byte array with the given RSA key string. """
    cipher = PKCS1_OAEP.new(key=RSA.import_key(key))

    modBits = number.size(cipher._key.n)
    k = number.ceil_div(modBits, 8)
    hLen = cipher._hashObj.digest_size
    length = k - 2 * hLen - 3

    res = []
    for i in range(0, len(message), length):
        res.append(cipher.encrypt(message[i:i + length]))
    return b"".join(res)

def decrypt(key, message):
    """ Decrypts the given byte array with the given RSA key string. """
    private_key = RSA.import_key(key)
    decipher = PKCS1_OAEP.new(key=private_key)

    length = private_key.size_in_bytes()

    res = []
    for i in range(0, len(message), length):
        decrypted_block = decipher.decrypt(message[i:i + length])
        res.append(decrypted_block)
    return b"".join(res)

def receivePackets(socket, size=4096):
    """ Receives all incoming packets from the socket until the end of the message. """
    data = socket.recv(size).split(b" ", 1)
    dataSize = int(data[0].decode())
    data = data[1]
    while len(data) != dataSize:
        data += socket.recv(size if dataSize - len(data) >= size else dataSize - len(data))
    return data

def sendPackets(socket, message, size=4096):
    """ Sends a message to a socket. Adds the length of the message at the beginning. """
    socket.sendall(str(len(message)).encode("utf-8") + b" " + message)