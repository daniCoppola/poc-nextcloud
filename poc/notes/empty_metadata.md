Title: Desktop clients uses a metadata key of all zeros in end-to-end encryption when the server returns an empty list of metadata keys. 
## Summary:
This attack exploits an implementation bug. Specifically,
when the client processes the folder metadata retrieved from the server, no
error is generated if the metadata does not contain any metadata keys. As a
consequence, when the client tries to encrypt a file metadata, the metadata
key used consists of all zeros. This is because when accessing the empty map
of metadata keys, a pointer to a section of memory containing all zeros is
returned and cast to a char pointer. An adversary can remove all the metadata keys
from the folder metadata and trigger this bug.

The following paragraph gives more details about the objects used in the code 
and their expected behavior. The object used to store metadata keys is of type
QMap [3]. The documentation states that when a map is accessed at an index
not present in the map, a default constructed value is inserted in the map
and returned [4]. The metadata keys contained in the map are QByteArray
objects, and the default value for a QByteArray is a null byte array[5].
In essence, a null byte array is a pointer to a section of memory containing all zeros.

To exploit this bug, the adversary returns the following metadata
``` 
   {
    "files": {
            "dummy": {
                "authenticationTag": "",
                "encrypted": "",
                "initializationVector": "",
                "metadataKey": 0
            }
        },
        "metadata": {
            "metadataKeys": {}
        }
    } 
```
on the first time the client fetches the metadata. The client sets up the metadata executing 
function setUpExistingMetadata  in clientsideencryption.cpp [2]. The dummy file is included
to ensure that the map (originally empty) of metadata keys is accessed at index 0. 
As explained previously, this will insert a null byte array at index zero.
During metadata encryption, the client will use this value as a key to encrypt the files' metadata. 

In conclusion, if a client receives a folder metadata with no metadata keys,
files' metadata will be encrypted with an all zeros key.
 
## Steps to reproduce the vulnerability:

To simplify the process of reproducing the vulnerability, we created a Nextcloud server instance at http://140.238.220.26/nextcloud/.  The server is running version 24 of the Nexcloud server. 
The server code was modified in the following ways:
- the server returns an empty list of metadata keys and a dummy metadata file on the first time the client fetches the metadata.
- a python script is notified on each file upload. The script is responsible for decrypting the newly added files.
The server code can be found in the folder /var/www/nextcloud.
The modification made to the server code can be seen by looking at the git history and are also enclosed in the code with comments 
"// BEGIN ATTACK CODE" and "// END ATTACK CODE".

 The vulnerability was tested for:
- ubuntu client stable version 3.6
- ubuntu client installed via snap

Attack setup:
  1. SSH into the server
  2. Change directory to /var/www/nextcloud/poc
  3. Start the script attack_server.py executing the command 
        ```sudo python3 attack_server.py e2e_empty_metadata```

The script will decrypt the uploaded metadata and files using all zeros as metadata key. 

Steps to reproduce:
    1. Connect with your desktop client to http://140.238.220.26/nextcloud
    2. Create a folder and mark it as end-to-end encrypted
    3. Create a text file in the folder and let the client sync
The python script will display the decrypted folder metadata and the recovered plaintext. 

## Mitigation:
This attack can be easily prevented. Before accessing the map at index index, a check should verify that the map contains an item at the specific index.
More in general, when developing end-to-end encryption systems, the inputs provided by the server should not be trusted and therefore always checked.
If the client treated the metadata folder received by the server as an untrusted input, it would check that at least one metadata key is present and abort the operation if the section is empty. 

## Supporting Material/References:

[1] https://github.com/nextcloud/desktop/blob/6249310173bc8adca6f9f9f22772d6f0979175d5/src/libsync/propagateuploadencrypted.cpp#L120

[2] https://github.com/nextcloud/desktop/blob/6249310173bc8adca6f9f9f22772d6f0979175d5/src/libsync/clientsideencryption.cpp#L1467

[3] https://doc.qt.io/qt-6/qmap.html

[4] https://doc.qt.io/qt-6/qmap.html#operator-5b-5d-1

[5] https://doc.qt.io/qt-6/qbytearray.html#QByteArray