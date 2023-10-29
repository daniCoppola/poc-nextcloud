from Crypto.Random import get_random_bytes
import json
import glob
import os

from pathlib import Path

from mysql.connector import connect

class db():
    def __init__(self):
        self.username = 'username'
        self.password = 'password'
        self.database = 'nextcloud'

    def update_file(self, file_name, checksum):
        with connect(username = "username",
                     password = 'password',
                      database = 'nextcloud') as connection:
            cursor = connection.cursor()
            update = f"""UPDATE oc_filecache 
                         SET encrypted = 0,
                             etag = 'ff464cb7335e56a1aae87a91dfff',
                             checksum = 'SHA1:{checksum}'
                         WHERE name = '{file_name}' and NOT path LIKE '%encryption%' """
            cursor.execute(update)
            connection.commit()

    def rm_file(self, file_path:Path):
        file_name = file_path.name
        parent = file_path.parent
        print(parent)
        with connect(username = "username",
                     password = 'password',
                      database = 'nextcloud') as connection:
            cursor = connection.cursor()
            delete = f"""DELETE from oc_filecache WHERE name = '{file_name}'"""
            cursor.execute(delete)
            connection.commit()

    def get_id(self, file_name: str):
        with connect(username = "username",
                     password = 'password',
                      database = 'nextcloud') as connection:
            cursor = connection.cursor()
            select = f"""SELECT fileid from oc_filecache WHERE name = '{file_name}' LIMIT 1"""
            cursor.execute(select)
            return next(cursor)[0]

class ServerPath():
    def __init__(self,config):
        self.config = config["server"]
        self.base_path = Path(self.config["base_path"])
        self.conf_path = self.base_path / "config/config.php"
        self.data_path = self.base_path / "data"
        self.db = db()

    def extractInfoFromUri(self, uri):
        "/dav/files/3/tmp/4daf470df101491c87c72b831b383e0b"
        "/var/www/nextcloud/data/3/files/s/716eb7ec179d48958c81c87fc64f1d81.e2e-to-save-11.16-03.58.vs"
        file = uri.split("/")[-1].split("-")[0]
        dir = uri.split("/")[-2]
        uid = uri.split("/")[-3]
        return dir, file, uid

    def getFilePath(self, uri):
        relative = uri[4:]
        self.data_path / relative

    def getRecentVersions(self, uri, n = 1): #TODO get also the metadata version
        file = uri.split("/")[-1]
        dir  = uri.split("/")[-2]
        uid  = uri.split("/")[-3]
        path = f"/{uid}/files/{dir}/{file}"
        list_of_files = glob.glob(str(self.data_path) + f"{path}*.vs")
        latest_files = sorted(list_of_files, key=os.path.getctime, reverse=True)[:n]
        list_of_metadata = glob.glob(str(self.metadataPath(dir)) + "*")
        latest_metadatas = sorted(list_of_metadata, key=os.path.getctime, reverse=True)[:n]
        return latest_files, latest_metadatas

    def SSEFilePath(self, uid, path):
        return self.data_path / uid / "files" / path

    def SSEKeyPath(self, uid, file_path:Path):
        return self.data_path / uid / "files_encryption/keys/files/" / file_path / "OC_DEFAULT_MODULE/"

    def serverPkeyPath(self):
        return self.data_path / f"files_encryption/OC_DEFAULT_MODULE/{self.config['pkey']}"

    def serverSkeyPath(self):
        return self.data_path / f"files_encryption/OC_DEFAULT_MODULE/{self.config['skey']}"

    def E2EEFilePath(self,file_path, uid):
        return self.data_path / f"{uid}/files"/ file_path

    def E2EEPublicKeyPath(self, uid):
            return self.data_path /  f"{self.config['appdata']}/end_to_end_encryption/public-keys/{uid}.public.key"

    def metadataPath(self, folder_name):
        return self.data_path / f"{self.config['appdata']}/end_to_end_encryption/meta-data/{self.db.get_id(folder_name)}/meta.data"
