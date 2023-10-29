Title: IV reuse in end-to-end encryption allows a malicious server to break confidentiality and authenticity.

## Summary:
The vulnerability consists of a nonce reuse when an end-to-end encrypted (E2EE) file is updated.
The function PropagateUploadEncrypted::slotFolderEncryptedMetadataReceived  is executed when a file is modified in an end-to-end encrypted folder [1]. The nonce is freshly generated ONLY if the file is new. Consequently, when a file is updated the same nonce is reused. 
Files are encrypted using AES-GCM.  AES-GCM is an AEAD scheme obtained by combining AES-CTR
with a Carter-Wegman MAC. A nonce reuse in AES-GCM leads to a complete loss of confidentiality and authenticity.

AES-GCM is similar to a one-time-pad where the keystream used to mask the plaintext is the encryption of the counters. If a counter is repeated under the same key, the keystream will also repeat and consequently, the XOR of the ciphertext will yield the XOR of the plaintext. The problem of recovering p1 and p2 given p1 ⊕ p2 is well studied in the cryptography literature, in [4] the authors show how to build a language model
that can separate p1 and p2 if the language of the underlying plaintext is known.
 For a proof of concept, we considered a simplified case in which an end-to-end encrypted text file is modified by adding or removing a single character. (e.g. original file = "Helloo, how are you doing today?", modified file = "Hello, how are you doing today?").
If a nonce is reused, Joux’s forbidden attack [2] can be used to recover the tagging key.  
Together the plaintext recovery attack and the Joux's forbidden attack allow an adversary to create valid ciphertexts that decrypt to a controlled plaintext. 

## Steps To Reproduce:
To simplify the process of reproducing the vulnerability, we created a Nextcloud server instance at http://140.238.220.26/nextcloud/.  The server is running version 24 of the Nexcloud server. 
The server code was modified in the following ways:
- each file version is stored, instead of only the most recent one
- a python script is notified on each file upload. The script is responsible for recovering the plaintext and the tagging key.
The server code can be found in the folder /var/www/nextcloud.
The modification made to the server code can be seen by looking at the git history and are also enclosed in the code with comments 
"// BEGIN ATTACK CODE" and "// END ATTACK CODE".

 The vulnerability was tested for:
- ubuntu client stable version 3.6
- ubuntu client installed via snap [5]

Attack setup:
  1. SSH into the server
  2. Change directory to /var/www/nextcloud/poc
  2. Start the script attack_server.py executing the command 
      ```sudo python3 attack_server.py e2e_repeated_iv```
The script output will show the attack steps and the recovered plaintext.

Steps to reproduce:
    1. Connect with your desktop client to http://140.238.220.26/nextcloud
    2. Create a folder and mark it as end-to-end encrypted
    3. Create a text file in the folder and let the client sync
    4. Modify the text file by deleting one character
    5. Create a new file to trigger a sync
    6. Check the file content

The python script will display the recovered plaintext. Moreover, after step 5, the file content is modified by the server to a chosen message showing that authenticity is also broken. 

## Mitigation:
This attack can be easily prevented by ALWAYS resampling nonce used for file encryption for both new and existing files.

TODO: add ssh keys, add zipped version of the server and of the attack code.

## Supporting Material/References:

[1]  https://github.com/nextcloud/desktop/blob/6249310173bc8adca6f9f9f22772d6f0979175d5/src/libsync/propagateuploadencrypted.cpp#L120

[2] Antoine Joux. Authentication failures in nist version of gcm. NIST Comment, page 3, 2006.

[4] Joshua Mason, Kathryn Watkins, Jason Eisner, and Adam Stubblefield.A natural language approach to automated cryptanalysis of two-time

pads. In Proceedings of the 13th ACM Conference on Computer and Communications Security, CCS ’06, page 235–244, New York, NY, USA,
2006. Association for Computing Machinery.

[5] https://snapcraft.io/nextcloud
