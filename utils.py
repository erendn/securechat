import json
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import MD5, SHA, SHA1, SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util import number
from binascii import hexlify


def readFile(path):
    try:
        file = open(path + ".json", "r")
        data = json.loads(file.read())
        file.close()
        return data
    except:
        return None


def writeFile(path, content):
    with open(path + ".json", "w") as file:
        json.dump(content, file)
        file.close()


def generateKeys():
    private = RSA.generate(1024)
    public = private.publickey()
    keys = {}
    keys["private"] = private.export_key().decode()
    keys["public"] = public.export_key().decode()
    return keys


def encrypt(key, message):
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
    private_key = RSA.import_key(key)
    decipher = PKCS1_OAEP.new(key=private_key)

    length = private_key.size_in_bytes()

    res = []
    for i in range(0, len(message), length):
        decrypted_block = decipher.decrypt(message[i:i + length])
        res.append(decrypted_block)
    return b"".join(res)
