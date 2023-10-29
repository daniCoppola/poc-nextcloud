from Crypto.Random import get_random_bytes
import base64
import json
from pathlib import Path
from SSE import SSE
from Crypto.Cipher import AES
import string
import pycld2 as cld

def pprint(content, title):
    print("\n\n")
    print(title)
    print("-"*75)
    print(content)
    print("-"*75)
    print("\n\n")


def xor(a, b):
    return bytes([x^y for x,y in zip(a,b)])


class E2EE():

    def __init__(self, config, pathManager):
        # self.sse = SSE(config, pathManager)
        self.paths = pathManager
        self.metadataKey = bytes.fromhex(config["attack"]["metadataKey"])
        self.metadataKeyIndex = config["attack"]["metadataKeyIndex"]

    def decrypt_metadata(self, metadata, metadataKey):
        """Decrypts files' metadata using a metadata key

        Args:
            metadata (dictionaty): folder metadata
            metadataKey (bytes): metadata key

        Returns:
            dictionary: folder metadata with decrypted files' metadata
        """

        print(f"Decrypt metadata with {metadataKey} as key...")

        pprint(json.dumps(metadata, indent = 4), "Enc metadata:")
        dec_metadata = metadata.copy()
        for file, metadata_file in metadata["files"].items():
            try:
                print(f"Decrypting metadata for {file}")
                encrypted = metadata_file["encrypted"].split("|")
                ctxt_tag = base64.b64decode(encrypted[0])
                iv = base64.b64decode(encrypted[1])
                ctxt = ctxt_tag[:-16]
                tag = ctxt_tag[-16:]

                ptxt = self.symmetric_decryption(metadataKey, ctxt, tag, iv)
                print(base64.b64decode(ptxt).decode("ASCII"))
                dec_file_metadata = json.loads(base64.b64decode(ptxt).decode("ASCII"))
                dec_file_metadata["metadataKey"] = metadataKey.decode("ASCII")
                dec_metadata["files"][file]["encrypted"] = dec_file_metadata
                
            except:
                print("Error converting to json")

        pprint(json.dumps(dec_metadata, indent = 4), "Decrypted metadata")
        return dec_metadata

    def encrypt_file_metadata(self, metadata, metadataKey):
        """Encrypts files' metadata present in the folder metadata, metadata

        Args:
            metadata (dictionary): folder metadata
            metadataKey (byte): metadata key

        Returns:
            dictionary: folder metadata with encrypted files' metadata
        """
        print( f"Encrypting metadata with metdata key: {metadataKey}")
        ptxt = base64.b64encode(json.dumps(metadata).encode())
        iv = get_random_bytes(16)
        ctxt, tag = self.symmetric_encryption(metadataKey, ptxt, iv)
        ctxt_tag = base64.b64encode(ctxt + tag).decode("ASCII")
        encrypted = ctxt_tag + "|" + base64.b64encode(iv).decode("ASCII")
        return encrypted

    def decrypt_e2ee(self, file_metadata, file_path: Path):
        """Decrypts a file using file key, tag and iv from the file_metadata

        Args:
            file_metadata (dictionary): file metadata containing key, tag and iv used int the file encryption
            file_path (Path): path to the E2EE file

        Returns:
            bytes: decrypted file
        """
        try:
            with open(file_path, "rb") as f:
                ctxt = f.read()
        except:
            print("File does not exists...")
            return
        try:
            iv = base64.b64decode(file_metadata["initializationVector"])
            tag = base64.b64decode(file_metadata["authenticationTag"])
            key = base64.b64decode(file_metadata['encrypted']["key"])

            print(f"File key: {key}")
            ptxt = self.symmetric_decryption(key, ctxt[:-16], tag, iv)
            pprint(ptxt, f"Recovered plaintext for file {file_metadata['encrypted']['filename']}:")
            return ptxt

        except:
            print(f"Continue...")

    def encrypt_e2ee(self, ptxt, original_name):
        """Encryts plaintext and generates file metadata

        Args:
            ptxt (bytes): plaintext to encrypt
            original_name (str): name of the file

        Returns:
            bytes, str, dictionary: The encryption of ptxt, the obfuscated name used to store the file on the server, and
                                    the file metadata
        """
        # encrypt the file e2ee
        file_key = b"A"*16
        iv = get_random_bytes(16)
        ctxt, tag = self.symmetric_encryption(file_key, ptxt, iv)
        obf_name = get_random_bytes(16).hex()
        file_metadata = {}
        file_metadata["initializationVector"] = base64.b64encode(iv).decode()
        file_metadata["authenticationTag"] = base64.b64encode(tag).decode()
        
        # create encrypted metadata 
        encrypted = {}
        encrypted["filename"] = original_name
        encrypted["key"]      = base64.b64encode(file_key).decode()
        encrypted["mimetype"] = "text/plain"
        encrypted["version"]  = 1
        file_metadata["encrypted"] = self.encrypt_file_metadata(encrypted, self.metadataKey)
        file_metadata["metadataKey"] = self.metadataKeyIndex
        return ctxt + tag, obf_name, file_metadata

    def symmetric_decryption(self, key, ctxt, tag, iv):
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            ptxt = cipher.decrypt(ctxt)
            try:
                cipher.verify(tag)
            except ValueError:
                print("Key incorrect or message corrupted")
                #exit()
            return ptxt

    def symmetric_encryption(self, key, ptxt, iv):
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        ctxt, tag = cipher.encrypt_and_digest(ptxt)
        return ctxt, tag

    def decrypt_repeated_iv(self, ctxt1, ctxt2):
        """ Given two ciphertext encrypted using GCM with the same IV,
            it recovers the plaintext. The assumption is that that the
            two underlying plaintexts differ by one character, e.g.
            ptxt1: Hii, my name is Daniele
            ptxt2: Hi, my name is Daniele

        Args:
            ctxt1 (bytes): ctxt corresponding to the first encrypted version of a file
            ctxt2 (bytes): ctxt orresponding to the second ecrypted version of a file

        Returns:
            bytes, int: recovered plaintext, index of the modified char
        """ 
        # keep the longer file in ctxt1 and always treat the modification
        # as a deletion
        if len(ctxt2) > len(ctxt1):
            ctxt0 = ctxt2
            ctxt2 = ctxt1
            ctxt1 = ctxt0
        deletion_length = len(ctxt1) - len(ctxt2)
        ptxt_xor =  bytes([x ^ y   for x, y in zip(ctxt1, ctxt2)])
        modification_index = 0
        while ptxt_xor[modification_index] == 0:
            modification_index += 1
        if deletion_length == 1:
            for i, a in enumerate(string.ascii_letters):
                decrypted = self.decrypt_two_time_pad(ptxt_xor, modification_index, a.encode())
                if decrypted is not None:
                    pprint(decrypted, "IV repeated! Recovered plaintext:")
                    return decrypted.encode(), modification_index
        return None, None
        
    def decrypt_two_time_pad(self,ptxt_xor, modification_index, guess):
        """

        Args:
            ptxt_xor (bytes): xor of two plaintext
            modification_index (int): index of the deleted/inserted character
            guess (char): guess for the deleted/insterted character

        Returns:
            bytes: plaintext after the character modification
        """
        start_guess = guess
        decrypted = b""
        pos = modification_index
        l = len(guess)
        while pos + l < len(ptxt_xor):
            guess = xor(ptxt_xor[pos:pos + l], guess)
            decrypted += guess
            pos += l
        decrypted += xor(ptxt_xor[pos:], guess)
        try:
            decrypted = decrypted.decode("ASCII") 
            print(f"Guess: {start_guess}\n{decrypted}\n")
            if cld.detect(decrypted)[0]:
                return decrypted
        except:
            return None