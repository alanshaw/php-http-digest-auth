<?php

/*
	Copyright 2010 Alan Shaw
	http://www.freestyle-developments.co.uk

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and limitations
	under the License.
*/

	/**
	 * Object orientated PHP HTTP digest authentication.
	 *
	 * Extend this class and implement abstract functions to create your own
	 * HTTP digest authentication implementation.
	 */
	abstract class HTTPDigestAuth {

		////////////////////////////////////////////////////////////////////////
		// @public

		/**
		 * @return an authenticated user object on success, null otherwise.
		 */
		public function authenticate() {

			if(empty($_SERVER['PHP_AUTH_DIGEST'])) {
				$this->setHeadersUnauthorized();
				$this->getResponseBodyUnauthorized();
				return null;
			}

			$authClientData = new HTTPDigestAuthClientData($_SERVER['PHP_AUTH_DIGEST']);

			// Check for stale nonce
			if($this->isStaleNonce($authClientData->nonce)) {
				$this->setHeadersUnauthorized(true);
				$this->getResponseBodyUnauthorized();
				return null;
			}

			// Check for correct nonce count
			if($authClientData->nc != $this->getNonceCount($authClientData->nonce) + 1) {
				$this->setHeadersBadRequest();
				$this->getResponseBodyBadRequest('Incorrect nonce count');
				return null;
			}

			$this->incrementNonceCount($authClientData->nonce);

			// Check request URI is the same as the auth digest uri
			if($authClientData->uri != $_SERVER['REQUEST_URI']) {
				$this->setHeadersBadRequest();
				$this->getResponseBodyBadRequest('Digest auth URI != request URI');
				return null;
			}

			// Check opaque is correct
			if($authClientData->opaque != $this->getOpaque()) {
				$this->setHeadersBadRequest();
				$this->getResponseBodyBadRequest('Incorrect opaque');
				return null;
			}

			// Check user exists
			if(!$this->userExists($authClientData->username)) {
				$this->setHeadersUnauthorized();
				$this->getResponseBodyUnauthorized();
				return null;
			}

			$ha1 = $this->getHA1ForUser($authClientData->username);

			// Generate A2 hash
			if($authClientData->qop == 'auth-int') {
				$a2 = $_SERVER['REQUEST_METHOD'] . ':' . stripslashes($_SERVER['REQUEST_URI']) . ':' . file_get_contents('php://input');
				$ha2 = md5($a2);
			} else {
				$a2 = $_SERVER['REQUEST_METHOD'] . ':' . stripslashes($_SERVER['REQUEST_URI']);
				$ha2 = md5($a2);
			}

			// Generate the expected response
			if($authClientData->qop == 'auth' || $authClientData->qop == 'auth-int') {
				$expectedResponse = md5($ha1 . ':' . $authClientData->nonce . ':' . $authClientData->nc . ':' . $authClientData->cnonce . ':' . $authClientData->qop . ':' . $ha2);
			} else {
				$expectedResponse = md5($expectedResponse = $ha1 . ':' . $authClientData->nonce . ':' . $ha2);
			}

			// Check request contained the expected response
			if($authClientData->response != $expectedResponse) {
				$this->setHeadersBadRequest();
				$this->getResponseBodyBadRequest();
				return null;
			}

			return $this->getUser($authClientData->username);
		}

		////////////////////////////////////////////////////////////////////////
		// @private

		private function setHeadersUnauthorized($stale = false) {

			header('HTTP/1.1 401 Unauthorized');

			$authHeader = 'WWW-Authenticate: Digest realm="' . $this->getAuthRealm() . '",qop="auth-int,auth",algorithm="MD5",nonce="' . $this->createNonce() . '",opaque="' . $this->getOpaque() . '"';

			if($stale) {
				$authHeader .= ',stale=TRUE';
			}

			header($authHeader);
		}

		private static function setHeadersBadRequest() {
			header('HTTP/1.1 400 Bad Request');
		}

		////////////////////////////////////////////////////////////////////////
		// @optional

		protected function getResponseBodyUnauthorized($reason = '') {
?>
<!DOCTYPE HTML>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<title>Error</title>
	</head>
	<body>
		<h1>401 Unauthorized.</h1>
<?php
	if($reason) {
?>
		<p><?php echo htmlspecialchars($reason); ?></p>
<?php
	}
?>
	</body>
</HTML>
<?php
		}

		protected function getResponseBodyBadRequest($reason = '') {
?>
<!DOCTYPE HTML>
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
		<title>Error</title>
	</head>
	<body>
		<h1>400 Bad Request.</h1>
<?php
	if($reason) {
?>
		<p><?php echo htmlspecialchars($reason); ?></p>
<?php
	}
?>
	</body>
</HTML>
<?php
		}

		////////////////////////////////////////////////////////////////////////
		// @required

		/**
		 * Gets the authentication realm for this class
		 *
		 * @return String
		 */
		abstract protected function getAuthRealm();

		/**
		 * Gets the opaque for this class
		 *
		 * @return String
		 */
		abstract protected function getOpaque();

		/**
		 * Creates a new nonce to send to the client
		 *
		 * @return String
		 */
		abstract protected function createNonce();

		/**
		 * Returns whether or not this nonce has expired. Should return true for
		 * non existent nonce.
		 *
		 * @param String $nonce
		 * @return Boolean
		 */
		abstract protected function isStaleNonce($nonce);

		/**
		 * Gets the current request count for a particular nonce
		 *
		 * @param String $nonce The nonce to get the count of
		 * @return uint The current nonce count
		 */
		abstract protected function getNonceCount($nonce);

		/**
		 * Increments the nonce count by 1
		 *
		 * @param String $nonce The nonce to increment
		 */
		abstract protected function incrementNonceCount($nonce);

		/**
		 * Returns a boolean indicating whether or not a user with the specified
		 * username exists.
		 *
		 * @param String $username
		 * @return Boolean
		 */
		abstract protected function userExists($username);

		/**
		 * Returns the A1 hash for the specified user.
		 * i.e. return md5('username:realm:password')
		 *
		 * @param String $username
		 * @return String
		 */
		abstract protected function getHA1ForUser($username);

		/**
		 * Returns a user instance that belongs to the user with the username
		 * provided.
		 *
		 * @param String $username
		 * @return ???
		 */
		abstract protected function getUser($username);
	}

	/**
	 * @private
	 */
	class HTTPDigestAuthClientData {

		public $username;
		public $nonce;
		public $nc;
		public $cnonce;
		public $qop;
		public $uri;
		public $response;
		public $opaque;

		public function __construct($header) {

			preg_match_all('@(username|nonce|uri|nc|cnonce|qop|response|opaque)=[\'"]?([^\'",]+)@', $header, $t);

			$data = array_combine($t[1], $t[2]);

			$this->username = $data['username'];
			$this->nonce = $data['nonce'];
			$this->nc = $data['nc'];
			$this->cnonce = $data['cnonce'];
			$this->qop = $data['qop'];
			$this->uri = $data['uri'];
			$this->response = $data['response'];
			$this->opaque = $data['opaque'];
		}
	}
?>