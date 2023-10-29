from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.Cipher import AES, ARC4, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA1, SHA512, SHA256, HMAC
from Crypto.Random import get_random_bytes
import base64
import json
from Crypto.Util import Counter
import re

class SSE():

    def __init__(self, config, pathManager):
        self.paths = pathManager
        self.config_client = config["client"]
        self.config_server = config["server"]
        
        self.global_dec_key = None
        self.global_tag_key = None

        with open(self.paths.conf_path)as f:
            while 1:
                line = f.readline()
                if 'secret' in line:
                    self.secret = line.split('=>')[1].strip(" ,'\n\t").encode()
                    break

        with open(self.paths.serverPkeyPath()) as f:
            s = f.read()
        pkey = base64.b64decode(json.loads(self.decryptSymmetric(s))["key"])
        self.public_key = RSA.import_key(pkey)

        #with open(self.paths.serverSkeyPath()) as f:
        with open("./master.private.key") as f:
            s = f.read()
        #skey = base64.b64decode(json.loads(self.decryptSymmetric(s))["key"])

        self.private_key = RSA.import_key(s)

    def decryptSymmetric(self, ctxt, unpad=lambda s: s[0:-s[-1]]):

        split = ctxt.split("|")
        ctxt = bytes.fromhex(split[0])
        iv = bytes.fromhex(split[1])
        tag = bytes.fromhex(split[2])

        enc_key, tag_key = self.deriveSymmetricKey()
        cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
        ptxt = unpad(cipher.decrypt(ctxt))
        return ptxt.decode()

    def _pad(self, data, block_size=16):
        pad = block_size - (len(data) % block_size)
        return data + pad * chr(pad).encode()

    def is_sse(self, path):
        file_path =  self.paths.SSEFilePath(self.config_client["uid"], path)
        with open(file_path, "rb") as f:
            line = f.readline()
        return b"oc_encryption_module" in line

    def encryptSymmetric(self, ptxt):
        ptxt = self._pad(ptxt)
        # TODO check padding
        iv = b"a"*16
        enc_key, tag_key = self.deriveSymmetricKey()
        cipher = AES.new(enc_key, AES.MODE_CBC, iv=iv)
        ctxt = cipher.encrypt(ptxt)
        hmac = HMAC.new(tag_key, digestmod=SHA256)  # TODO check digestmode
        hmac.update(ctxt + iv)
        tag = hmac.digest()
        return ctxt.hex() + "|" + iv.hex() + "|" + tag.hex()

    def deriveSymmetricKey(self):
        if self.global_dec_key is not None:
            return self.global_dec_key, self.global_tag_key
        # keys is the hex encodede output of the hkdf on the secret of the server
        salt = b"\x00" * 16
        key_material = HKDF(self.secret, 64, salt, SHA512, 1)
        self.global_dec_key = PBKDF2(
            key_material[:32], "phpseclib", count=1000, hmac_hash_module=SHA1)
        self.global_tag_key = PBKDF2(
            key_material[32:], "phpseclib", count=1000, hmac_hash_module=SHA1)
        return self.global_dec_key, self.global_tag_key

    def getFileKey(self, key_path):
        print(f"Recovering share key at {key_path}...")
        key_share =  key_path / f"master_{self.config_server['master']}.shareKey"
        with open(key_share) as f:
            ctxt = f.read()

        share_key = base64.b64decode(json.loads(
            self.decryptSymmetric(ctxt))["key"])

        print("Recovering file key...")
        with open(key_path / "fileKey") as f:
            ctxt = f.read()

        file_key = base64.b64decode(json.loads(
            self.decryptSymmetric(ctxt))["key"])

        cipher = PKCS1_v1_5.new(self.private_key)
        sentinel = get_random_bytes(16)
        random_key = cipher.decrypt(share_key, sentinel)
        cipher = ARC4.new(random_key)
        file_key = cipher.decrypt(file_key)
        if file_key == sentinel:
            raise ValueError("ERROR")

        return file_key

    def createSignature(self, file_key, data):
        hash = SHA512.new()
        hash.update(file_key + b"_" + b"4" + b"_" + b"0end" + b"a")
        tag_key = hash.digest()
        print(f"Tag key {tag_key.hex()}")
        hmac = HMAC.new(tag_key, digestmod=SHA256)
        hmac.update(data)
        signature = hmac.hexdigest() + "xxx"
        return signature

    def decryptFile(self, file_path, uid):
        full_path =  self.paths.SSEFilePath(self.config_client["uid"], file_path)
        with open(full_path, "rb") as f:
            file = f.read().split(b"HEND")

        header = file[0].decode().split(":")[1:]
        ctxt = file[1].strip(b"-")
        cipher = header[header.index("cipher") + 1]
        ctxt, iv, sig = re.split(b"00iv00|00sig00", ctxt)
        key_path = self.paths.SSEKeyPath(uid, file_path)
        file_key = self.getFileKey(key_path)

        counter = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
        cipher = AES.new(file_key, AES.MODE_CTR, counter=counter)
        ptxt = cipher.decrypt(base64.b64decode(ctxt))
        return ptxt