## Summary:
 Metadata keys are encrypted using the user’s master key with RSA-OAEP. While providing confidentiality and integrity, RSA-OAEP
does not provide authentication. Consequently, anyone who has access to the user’s public key can generate valid encryption of a metadata key. This
is especially problematic because, on every sync between client and server, the metadata file is re-encrypted by the client using the latest metadata key
associated with the highest index. The lack of authenticity allows a malicious server to induce the client into using a metadata key known to the server.
After the server modifies the folder metadata, any update to the E2EE folder from the client will cause the file metadata to be encrypted with the rogue
metadata key. The client downloads the folder metadata from the server, decrypt the metadataKeys and uses the latest one to create the updated version of the folder metadata.

## Steps to reproduce the vulnerability:

To simplify the process of reproducing the vulnerability, we created a Nextcloud server instance at http://140.238.220.26/nextcloud/.  The server is running version 24 of the Nexcloud server. 
The server code was modified in the following ways:
- the server adds a chosen metadata key encrypted under the user's public key to the folder metadata.
- a python script is notified on each file upload. The script is responsible for decrypting the uploaded files.
The server code can be found in the folder /var/www/nextcloud.
The modification made to the server code can be seen by looking at the git history and are also enclosed in the code with comments 
"// BEGIN ATTACK CODE" and "// END ATTACK CODE".

 The vulnerability was tested for:
- ubuntu client stable version 3.6
- ubuntu client installed via snap [5]


Attack setup:
  1. SSH into the server
  2. Change directory to /var/www/nextcloud/poc
  3. Start the script attack_server.py executing the command 
        ```sudo python3 attack_server.py e2e_add_metadata```

The script will decrypt the uploaded metadata and files using the chosen metadata key. 

Steps to reproduce:
    1. Connect with your desktop client to http://140.238.220.26/nextcloud
    2. Create a folder and mark it as end-to-end encrypted
    3. Create a text file in the folder and let the client sync
The python script will display the recovered plaintext. 

## Mitigation:
Metadata keys must be authenticated, or else a malicious server can pick the metadata key used by the client,
effectively gaining full access to the end-to-end folder. The current design encrypts metadata keys with RSA-OAEP,
which provides integrity and confidentiality, but it does not provide authenticity. From our understanding, the use of asymmetric cryptography was introduced for allowing folder sharing. 
Since sharing has not yet been implemented, we propose a mitigation that drops the sharing feature and prevents the presented attack. Moreover, after commenting on the sharing feature described in the white paper, we propose a major review of the E2EE module that would allow file sharing and prevent the presented attack.
 
If the sharing feature is removed, asymmetric encryption can be avoided and metadata keys can be protected using symmetric encryption schemes that provide confidentiality and authenticity. 
An additional symmetric key can be derived from the mnemonic and used to encrypt the metadata keys with an AEAD such as AES-GCM. The authenticated encryption scheme provides both confidentiality and authenticity, effectively stopping a malicious server from tampering with metadata keys.
To introduce this change, the metadata encryption should be modified to always encrypt metadata keys with the chosen AEAD. The metadata decryption should continue to support both the asymmetric and the symmetric versions. For all existing 
E2EE folders, a full re-encryption of the files under new file keys and metadata keys are necessary to ensure that no key material which might have been leaked is used to secure metadata or files. If we assume that no server collected the metadata keys and file keys of the clients, file re-encryption is not necessary.
When implementing patches that are backward compatible, it is important to ensure that downgrade attacks are possible. 
A malicious server trying to downgrade the patched version of E2EE to the original vulnerable version could always return the metadata folder with the metadata keys encrypted with RSA-OAEP. As long as clients
always encrypt the metadata using symmetric encryption, the server would not be able to get access to the newly added data. Each client could save a flag to memorize that a folder migrated to the new implementation. A client receiving the legacy folder metadata after migrating to the patched one should show an error and stop.

We briefly recap the sharing feature described in
the white paper, and point out some issues in the proposed design.

The current design uses the server as the root of trust of a PKI that binds users' with their public keys. 
When user A wants to share a folder with user B, it fetches the certificate of user B from the server,
validates it using the server's public key, and encrypts the latest metadata key with user's B public key.
The white paper also describes how user A could remove user B from the shared folder. 
User A should generate a new metadata key and encrypt it with the public key of all 
the users who have access to the folder except for user B. 
 
The current sharing design has three major issues. It is possible that the authors considered them, 
but they are not addressed in the white paper. 

Firstly, the PKI approach with the server as a root of trust has 
limited advantages in an adversarial setting where the server can be malicious. 
When user A asks the server for the public key of user B, a malicious server can generate a 
certificate binding user B to a chosen public key (corresponding to a
private key known to the server) and return it to user A.  
As a result, the client of user A will encrypt the metadata key to the server and not to user B.

Secondly, re-encrypting a new metadata key is not sufficient 
to remove a user from the share. If files are not re-encrypted
under new file keys, the removed user could save the file keys 
and decrypt files even after it was revoked access. With the current design, 
removing a user from a folder would require re-encrypting the entire folder. 
The white paper does not specify it and only mentions updating the metadata key. 
Note that the computation needed to remove a user from a shared folder is the 
same needed to create a new folder and share it with the new set of allowed users.

Finally, the list of users who have access to the shared folder is kept in the folder metadata 
and is not authenticated. Again, a malicious server can trivially add itself to the list and trick 
a client into encrypting the metadata key to its own public key. 
The list of users with access to the folder should be authenticated and, 
only members of the share should be allowed to add or remove others.

Based on the previous observations we propose a major modification to the current E2EE design. 
- Each user should have an asymmetric key pair. The distribution of public keys can be done over the server.
  Users should compare the fingerprint of their public keys out-of-band to bind a public key with a specific user. 

- Each folder should be associated with a single metadata key which is generated by the client who creates the folder. 
  The metadata key should be protected using signcryption. Confidentiality and authenticity ensure that a malicious server would not be able to recover the metadata key nor modify it. Each user with access to a shared folder should check who generated the metadata key and act accordingly. 

- Access revocation should not be supported. If a user needs to be removed from a shared folder, a new folder is created and all the files are re-encrypted. The metadata key is then signcrypted to the new set of users with access to the folder.

The proposed modifications require a major restructuring of the E2EE module. Since E2EE is still in development and given the 
various flaws that we pointed out, these major modifications should carefully be considered.

## Supporting Material/References:

