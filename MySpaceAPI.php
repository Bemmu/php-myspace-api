<?php

// BemmuSpace - PHP client for MySpace API.
// License: http://www.gnu.org/licenses/lgpl.txt
// Copyright Bemmu Sepponen, 2009
//
class MySpaceAPI {
	// Must be lowercase and only mention the port if it is not 80 for http or 443 for https.
	static $SERVER = 'http://api.myspace.com';

	// Try to act like the XML version, even though we are using JSON here. With this enabled
	// the library will act as a drop-in replacement for some other libraries, but will return
	// some duplicate keys.
	//
	public $xml_compatibility_mode = TRUE;

	// Options for debugging.
	//
	public $curl_verbose = 0; // set to 1 to see data passing between client and the server
	public $previous_base_string; // if server complains a signature was wrong, check this

	private $utf8_consumer_key;
	private $utf8_consumer_secret;

	function MySpaceAPI($utf8_consumer_key, $utf8_consumer_secret) {
		$this->utf8_consumer_key = $utf8_consumer_key;
		$this->utf8_consumer_secret = $utf8_consumer_secret;
	}

	// All the unreserved characters (letters, numbers, '-', '_', '.', '~') must not be 
	// encoded, while all other characters are encoded using the %XX format where XX is an 
	// uppercase representation of the character hexadecimal value.
	//
	static function urlencode($str) {
		$out = '';
		$str = (string)$str; // make sure not to start handling a number wrong
		for ($i=0; $i<strlen($str); $i++) {
			$ch = $str{$i};
			if (   ($ch >= 'A' && $ch <= 'Z')
			    || ($ch >= 'a' && $ch <= 'z')
			    || ($ch >= '0' && $ch <= '9')
			    || $ch == '-'
			    || $ch == '_'
			    || $ch == '.'
			    || $ch == '~') {
				$out .= $ch;
			} else {
				$out .= '%'.strtoupper(dechex(ord($ch)));
			}
		}
		return $out;
	}

	// When performing an HTTP query using OAuth, a special authorization header needs
	// to be included. However MySpace requires this to be included in the URI, not as a 
	// header, so there's an option to get that as well.
	//
	static function get_request_authorization_header($path, $signed_request, $as_uri_part=FALSE) {
		if (!$as_uri_part) {
			$auth = 'Authorization: OAuth realm="'.MySpaceAPI::$SERVER.'/'.$path.'"';
			foreach ($signed_request as $k => $v) {
				if (strpos($k, 'oauth_') === 0) {
					$auth .= ' ' . $k . '="' . $v . '"';
				}
			}
			return $auth;
		} else {
			$params = array();
			foreach ($signed_request as $k => $v) {
				if (strpos($k, 'oauth_') === 0) {
					$params[] = $k . '=' . $v;
				}
			}
			return implode('&', $params);
		}
	}

	// Returns a hash of arguments for a GET/PUT/POST/DELETE request including all the
	// necessary oauth fields, including a signature. Based on the tutorial at
	// http://www.hueniverse.com/hueniverse/2008/10/beginners-gui-1.html
	//
	// Only HMAC-SHA1 signature method and oauth version 1.0 supported.
	//
	public function get_signed_request($method, $path, $parameters, 
		$oauth_nonce, $oauth_timestamp) {

		$oauth_signature_method = 'HMAC-SHA1';
		$oauth_version = '1.0';

		// The OAuth Parameters and request parameters are collected together in
		// their raw, pre-encoded form. The parameters are collected from three locations: 
		// the URL query element (as defined by RFC 3986 section 3), the OAuth 'Authorization'
		// header (excluding the 'realm' parameter), and parameters included in a single-part 
		// 'application/x-www-form-urlencoded' POST body
		$raw_params = array(
			'oauth_consumer_key' => $this->utf8_consumer_key,
			'oauth_token' => '',
			'oauth_nonce' => $oauth_nonce,
			'oauth_timestamp' => $oauth_timestamp,
			'oauth_signature_method' => $oauth_signature_method,
			'oauth_version' => $oauth_version,
		);
		$raw_params = array_merge($raw_params, $parameters);

		// All text parameters are UTF-8 encoded (per section 5.1). Binary data is not
 		// directly handled by the OAuth specification but is assumed to be stored in an 
		// 8bit array which is not UTF-8 encoded. This step may not have any effect if the 
		// parameters are only using the ASCII character set.

		// After UTF-8 encoding, the parameters are URL-encoded.
		foreach ($raw_params as $k => $v) {
			$raw_params[$k] = MySpaceAPI::urlencode($v);
		}

		// The parameters are sorted (per section 9.1.1) first based on their encoded 
		// names, and if equal, based on their encoded values. Sort order is 
		// lexicographical byte value ordering which is the default string sort method in 
		// most languages, and means comparing the byte value of each character and 
		// sorting in an ascending order (which results in a case sensitive sort). It is 
		// important not to try and perform the sort operation on some combined string of 
		// both name and value as some known separators (such as '=') will cause the sort 
		// order to change due to their impact on the string value.
		$sorted_params = $raw_params;
		ksort($sorted_params, SORT_STRING);

		// Once encoded and sorted, the parameters are concatenated together into a single 
		// string. Each parameter's name is separated from the corresponding value by an 
		// '=' character (even if the value is empty), and each name-value pair is 
		// separated by an '&' character (per section 9.1.1). This method is similar to 
		// how HTML form data is encoded in 'application/x-www-form-urlencoded' but due 
		// to the specific encoding and sorting requirements, is often not fully 
		// compatible with existing libraries.
		$pairs = array();
		foreach ($sorted_params as $k => $v) {
			$pairs[] = $k.'='.$v;
		}
		$normalized_parameters = join('&', $pairs);

		// The request URL is normalized (per section 9.1.2) as 
		// scheme://authority:port/path as the query is already included in the list of
		// parameters and the fragment is excluded.
		$normalized_url = MySpaceAPI::$SERVER . '/' . $path;

		// To complete the creation of the Signature Base String - the input to the 
		// signature algorithm - all the request pieces must be put together into a 
		// single string. The HTTP method (such as GET, POST, etc.) which is a critical 
		// part of HTTP requests is concatenated together with the normalized URL and 
		// normalized parameters. The HTTP method must be in uppercase and each of these 
		// three pieces is URL-encoded (as defined above) and separated by an '&' (per 
		// section 9.1.3)
		$signature_base_string = $method.'&';
		$signature_base_string .= MySpaceAPI::urlencode($normalized_url).'&'; 
		$signature_base_string .= MySpaceAPI::urlencode($normalized_parameters); 
		$this->previous_base_string = $signature_base_string; // for debugging

		// The HMAC-SHA1 signature method uses the two secrets - Consumer Secret and 
		// Token Secret - as the HMAC-SHA1 algorithm key. To construct the key, each 
		// secret is UTF8-encoded, URL-encoded, and concatenated into a single string 
		// using an '&' character as separator even if either secret is empty (per 
		// section 9.2). Libraries should not assume the secrets are in plain ASCII text 
		// and ensure proper UTF-8-encoding and URL-encoding prior to concatenation.
		$secret_pair = MySpaceAPI::urlencode($this->utf8_consumer_secret) . '&' . '';

		// With the Signature Base String as the HMAC-SHA1 text and concatenated secrets 
		// as key, the Consumer generates the signature (per section 9.2.1). The 
		// HMAC-SHA1 algorithm will generate an octet string as the result. The octet 
		// string must be base64-encoded with '=' padding (per RFC 2045 section 6.8):
		$octet_string = hash_hmac('sha1', $signature_base_string, $secret_pair, $raw_output=TRUE);
		$base64_encoded = base64_encode($octet_string);

		// The calculated signature is added to the request using the 'oauth_signature' 
		// parameter. When the signature is verified by the Service Provider, this 
		// parameter is not included in the signature workflow as it was not part of the 
		// Signature Base String signed by the Consumer. When the signature is included 
		// in the HTTP request, it must be properly encoded as required by the method 
		// used to transmit the parameters.
		//
		// The other values in the request were urlencoded, so we shall also urlencode the
		// signature to be identical in form.
		$sig_ar = array('oauth_signature' => MySpaceAPI::urlencode($base64_encoded));
		$request = array_merge($raw_params, $sig_ar);
		return $request;
	}

	// Gets a cURL object initialized with opts common to GET and PUT methods.
	//
	static function curl_common_init($url, $verbose = 1) {
	        if (!function_exists('curl_init')) die('BemmuSpace library requires curl');
		$curl = curl_init();
		curl_setopt($curl, CURLOPT_URL, $url);
		curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($curl, CURLOPT_VERBOSE, $verbose);
		return $curl;
	}

	// Performs an HTTP request with a cURL object that has the desired options already set.
	// Returns the content or throws an exception.
	//
	static function curl_common_execute($curl) {
		$response_content = curl_exec($curl);
		$response_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
		curl_close($curl);
		if ($response_code == 200) {
			return $response_content;
		}
		throw new Exception($response_content);
	}

	// Performs a HTTP PUT with cURL, posting the given array of data to the given URL.
	// Returns the content or throws an exception.
	//
	static function curl_put($url, $data, $verbose = 0) {
		$curl = MySpaceAPI::curl_common_init($url, $verbose);
		curl_setopt($curl, CURLOPT_POST, 1);
		curl_setopt($curl, CURLOPT_HTTPHEADER, array('Expect:')); // turn off Expect: 100-continue
		curl_setopt($curl, CURLOPT_CUSTOMREQUEST, 'PUT');
		curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
		return MySpaceAPI::curl_common_execute($curl);
        }

	// Performs an HTTP GET with cURL to the given URL.
	// Returns the content or throws an exception.
	//
	static function curl_get($url, $verbose = 0) {
		$curl = MySpaceAPI::curl_common_init($url, $verbose);
		return MySpaceAPI::curl_common_execute($curl);
        }

	// Returns an OAuth URI part that can be appended to the path when doing a GET/PUT request.
	//
	private function get_oauth_uri_part($path, $method = 'GET', $data_array = NULL) {
		if (!$data_array) $data_array = array();
		$oauth_nonce = microtime().rand();
		$oauth_timestamp = time();
		$req = $this->get_signed_request(
			$method, 
			$path,
			$data_array,
			$oauth_nonce,
			$oauth_timestamp
		);
		return MySpaceAPI::get_request_authorization_header($path, $req, $as_uri_part=TRUE);
	}

	// Does an OAuth HTTP PUT to a MySpace path with the given array() of data.
	// Returns the content or throws an exception.
	//
	private function put($path, $data_array) {
		$auth = MySpaceAPI::get_oauth_uri_part($path, 'PUT', $data_array);
		return MySpaceAPI::curl_put(
			MySpaceAPI::$SERVER.'/'.$path.'?'.$auth, 
			http_build_query($data_array, '', '&'),
			$this->curl_verbose
		);
	}

	// Does an OAuth HTTP GET to a MySpace path. 
	// Returns the content or throws an exception.
	// 
	// If you need to include some GET variables, use the get_args parameter. Your
	// call will sporadically FAIL if you attempt to include them in the path. This
	// is because OAuth requires the args be sorted to a specific order.
	//
	private function get($path, $get_args = NULL) {
		if (!$get_args) $get_args = array();
		$auth = MySpaceAPI::get_oauth_uri_part($path, 'GET', $get_args);
		
		// The auth string will only contain oauth stuff, the args given to it are
		// only for the purposes of creating the signature. To get the get args
		// included, we still need to append them explicitly.
		$url = MySpaceAPI::$SERVER.'/'.$path;
		if (count($get_args) > 0) {
			$query = http_build_query($get_args, '', '&');
			$url .= '?'.$query.'&'.$auth;
		} else {
			$url .= '?'.$auth;
		}

		return MySpaceAPI::curl_get($url, $this->curl_verbose);
	}

	// Stores key & value pairs as appdata for the given user. At the time of writing
	// the size limit for the data was 1kB.
	//
	public function set_appdata($uid, $data_array) {
		$path = "v1/users/{$uid}/appdata.JSON";
		$this->put($path, $data_array);
	}

	// Retrieves the data stored by the method above. Returns NULL if there was no data.
	//
	public function get_appdata($uid) {
		$path = "v1/users/{$uid}/appdata.JSON";
		$array = json_decode($this->get($path), TRUE);

		// Rearrange the array such that it is a hash or keys and values.
		$nicer_hash = array();
		if (!isset($array['keyvaluecollection'])) return NULL;
		foreach ($array['keyvaluecollection'] as $hash) {
			$nicer_hash[$hash['key']] = $hash['value'];
		}
		return $nicer_hash;
	}

	// Given a user hash, makes it compatible with the old XML REST API key names by
	// adding keys by the old key names into the hash.
	//
	function get_xml_rest_api_compatible_user_hash($v) {
		if ($this->xml_compatibility_mode) {
                        if (isset($v['image'])) $v['imageuri'] = $v['image'];
                        if (isset($v['largeImage'])) $v['largeimageuri'] = $v['largeImage'];
                        if (isset($v['name'])) $v['displayname'] = $v['name'];
			return $this->add_lowercase_keys($v);
                }
		return $v;
	}

	// Returns a hash with several fields describing a single user. At the time of writing
	// a typical response would look like this:
	//
	// Array
	// (
	// 	[image] => http://b6.ac-images.myspacecdn.com/00832/63/09/832569036_s.jpg
	//	[largeImage] => http://b6.ac-images.myspacecdn.com/00832/63/09/832569036_l.jpg
	//	[name] => Bemmu
	//	[uri] => http://api.myspace.com/v1/users/85628343
	//	[userId] => 85628343
	//	[userType] => RegularUser
	//	[webUri] => http://www.myspace.com/85628343
	// )
	//
	// Sometimes users delete their accounts. In that case "name" will be null.
	//
	public function get_user($uid) {
		$path = "v1/users/{$uid}.JSON";
		$v = json_decode($this->get($path), TRUE);
		return $this->get_xml_rest_api_compatible_user_hash($v);
	}

	// Returns the given hash with keys in lower case added.
	//
	// In XML things were always in lower case, but in JSON they seem to be mixed case:
	// http://developer.myspace.com/Community/forums/p/668/36847.aspx#36847
	//
	private function add_lowercase_keys($hash) {
		foreach ($hash as $k => $v) {
			if (strtolower($k) != $k) {
				$hash[strtolower($k)] = $v;
			}
		}
		return $hash;
	}

	// Returns an array of friend hashes. Each hash being similar to what get_user would return
	// for that friend.
	//
	// You should probably do this using Javascript on client side, since this may take a long
	// time if the user has thousands of friends. I've had tasks on my server stalling for over
	// a minute, very likely because of such accounts.
	//
	// Can return an empty array without even Tom in it if this is a disabled user account.
	//
	public function get_all_friends($uid, $abort_page=50) {

		// Accumulate friends to an array of hashes one page at a time.
		$page_size = 100;
		$current_page = 0;
		$all_friends = array();
		do {
			// Get one page of friends.
			$current_page++;
			if ($current_page == $abort_page) break;
			$path = "v1/users/{$uid}/friends.JSON";
			$get_args = array('page_size' => $page_size, 'page' => $current_page);

			$response_content = $this->get($path, $get_args);
			$array = json_decode($response_content, TRUE);

			// Can have 0 friends if this is a disabled user account.
			if ($array['count'] == 0) return array();

			if (!isset($array['Friends'])) {
				throw new Exception("Couldn't find key 'Friends': $response_content");
			}

			foreach ($array['Friends'] as $k => $v) {
				$array['Friends'][$k] = $this->get_xml_rest_api_compatible_user_hash($v);
			}

			$all_friends = array_merge(
				$all_friends, 
				$array['Friends']
			);

			// From first page of friends we also learn how many pages there are.
			if (!isset($total_pages)) {
				if (!is_numeric($array['count'])) {
					throw new Exception("Count of friends was missing: $response_content");
				}
				$total_pages = ceil($array['count'] / (float)$page_size);
			}
		} while ($current_page < $total_pages);
		return $all_friends;
	}
}

?>
