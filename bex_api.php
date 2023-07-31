<?php

/* **********************
    beA.expert BEA-API / EXPERIMENTAL
    ---------------------------------
    Demo script not intented for production
    Version 1.2 / 29.12.2021
    (c) be next GmbH (Licence: GPL-2.0 & BSD-3-Clause)
    https://opensource.org/licenses/GPL-2.0
    https://opensource.org/licenses/BSD-3-Clause
    

    Dependency: 
    -----------
    http://phpseclib.sourceforge.net/

    ********************** */

error_reporting(E_ERROR | E_WARNING | E_PARSE);

include('Crypt/RSA.php'); // http://phpseclib.sourceforge.net/

global $bex_ident;
global $api_uri;
global $debug;

$debug = false;

if (file_exists("api.config.php")) {
    include("api.config.php"); // not public: bex_indent, cert etc ... only for beA.expert internal test
} else {

    $bex_ident = "......"; // to be completeted
    $api_uri = "https://......."; // to be completed
    $cert = 'c:\\token.p12'; // to be completed
    $pin = '123456'; // to be completed

}

function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}



function base64url_decode($data) {
    return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
}


function send_request($__req, $__func) {

    global $bex_ident;
    global $api_uri;
    global $debug;

    $curl_session = curl_init();
    curl_setopt($curl_session, CURLOPT_URL, $api_uri . $__func);
    curl_setopt($curl_session, CURLOPT_CONNECTTIMEOUT, 0);
    curl_setopt($curl_session, CURLOPT_TIMEOUT, 400);
    curl_setopt($curl_session, CURLOPT_RETURNTRANSFER, TRUE);
    curl_setopt($curl_session, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl_session, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($curl_session, CURLOPT_FORBID_REUSE, true); // SSL pooling and reuse of connection explicitly disabled
    curl_setopt($curl_session, CURLOPT_FRESH_CONNECT, true); // SSL pooling and reuse of connection explicitly disabled
    curl_setopt($curl_session, CURLOPT_POST, true);
    curl_setopt($curl_session, CURLOPT_CUSTOMREQUEST, "POST");
    curl_setopt($curl_session, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_0);
    curl_setopt($curl_session, CURLOPT_POSTFIELDS, 'j=' . base64url_encode($__req));
    curl_setopt(
        $curl_session,
        CURLOPT_HTTPHEADER,
        array(
            'Content-type: application/x-www-form-urlencoded',
            'bex-ident: ' . $bex_ident,
            'Expect:'
        )
    );

    if ($debug) {
        $fp = fopen(dirname(__FILE__) . '/api.curl.log', 'a');
        curl_setopt($curl_session, CURLOPT_VERBOSE, 1);
        curl_setopt($curl_session, CURLOPT_STDERR, $fp);
    }

    $result = curl_exec($curl_session);
    curl_close($curl_session);

    if ($debug) {
        echo ("result CURL:\n");
        print_r($result . "\n");
    }

    return $result;
}


function get_cert_file_values($file, $pass = '') {

    global $debug;

    if (!$cert_store = file_get_contents($file)) {
        echo "Fehler: Die Datei kann nicht geöffnet werden\n";
        exit;
    }

    if (openssl_pkcs12_read($cert_store, $cert_info, $pass)) {

        if ($debug) {
            echo "Zertifikatsinformationen\n";
            print_r($cert_info);
        }
        return $cert_info;
    } else {
        echo "Fehler: Das Zertifikat kann nicht gelesen werden.\n";
        exit;
    }
}


function decrypt_aes256cbc($encrypted, $key, $iv = '') {

    global $debug;

    if ($encrypted == '') {
        echo "decrypt_aes256cbc: no data to decode\n";
        return '';
    }

    if ($iv == '') {
        $iv = substr(base64_decode($encrypted), 0, 16);
        $encrypted = substr(base64_decode($encrypted), 16);
    } else {
        $iv = base64_decode($iv);
        $encrypted = base64_decode($encrypted);
    }

    $decrypted = '';
    $tag = "";

    if ($debug) {
        echo ("decrypt_aes256cbc:encrypted:$encrypted\n");
        echo ("decrypt_aes256cbc:key:$key\n");
        echo ("decrypt_aes256cbc:iv:$iv\n");
    }

    while (openssl_error_string() !== false);
    $decrypted = openssl_decrypt($encrypted, 'aes-256-cbc', base64_decode($key), OPENSSL_RAW_DATA, $iv, $tag);
    if ($debug) while ($msg = openssl_error_string()) echo $msg . "\n";

    return $decrypted;
}


function object2array($object) {
    return @json_decode(@json_encode($object), 1);
}


function simplexml_load_string_skip_ns($xml_string) {
    if (false === ($x1 = simplexml_load_string($xml_string))) return false;

    $namespaces = array_keys($x1->getDocNamespaces(true));
    $namespaces = array_filter($namespaces, function ($k) {
        return !empty($k);
    });
    $namespaces = array_map(function ($ns) {
        return "$ns:";
    }, $namespaces);

    return simplexml_load_string($ns_clean_xml = str_replace(
        array_merge(["xmlns="], $namespaces),
        array_merge(["ns="], array_fill(0, count($namespaces), '')),
        $xml_string
    ));
}

function bea_get_gericht_codes($token) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bex_get_gericht_codes');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }
    return json_decode($res, true);
}


function bea_login($cert_file, $cert_pin) {
    global $debug;

    $cert_info = get_cert_file_values($cert_file, $cert_pin);
    $thumprint = openssl_x509_fingerprint($cert_info["cert"], 'sha1', false);

    if ($debug) echo ("bea_login thumprint: $thumprint\n");

    $req["thumbprint"] = $thumprint;
    $login_step1_json = send_request(json_encode($req, JSON_UNESCAPED_SLASHES), 'bea_login_step1');

    $login_step1 = json_decode($login_step1_json);
    
    if (isset($login_step1->error)){
        return $login_step1;
    }

    if ($debug) {
        print $login_step1->{'challengeVal'};
        echo ("\n");
        print $login_step1->{'challengeValidation'};
        echo ("\n");
    }

    if (!openssl_sign(base64_decode($login_step1->{'challengeVal'}), $challenge_signed, $cert_info["pkey"], OPENSSL_ALGO_SHA256)) {
        echo "Fehler: challengeVal kann nicht signiert werden.\n";
        exit;
    }

    if (!openssl_sign(base64_decode($login_step1->{'challengeValidation'}), $validation_signed, $cert_info["pkey"], OPENSSL_ALGO_SHA256)) {
        echo "Fehler: challengeValidation kann nicht signiert werden.\n";
        exit;
    }

    return bea_login_step2($login_step1, $cert_info, $challenge_signed, $validation_signed);
}


function bea_login_step2($login_step1, $cert_info, $challenge_signed, $validation_signed) {

    global $debug;

    $req2["tokenPAOS"] = $login_step1->{'tokenPAOS'};
    $req2["userCert"] = base64_encode($cert_info["cert"]);
    $req2["challengeSigned"] = base64_encode($challenge_signed);
    $req2["validationSigned"] = base64_encode($validation_signed);

    $func2 = 'bea_login_step2';
    $login_step2_json = send_request(json_encode($req2, JSON_UNESCAPED_SLASHES), $func2);

    $login_step2 = json_decode($login_step2_json);

    if (isset($login_step2->error)){
        return $login_step2;
    }

    if ($debug) {
        print $login_step2->{'sessionKey'};
        echo ("\n");
        print $login_step2->{'validationKey'};
        echo ("\n");
    }

    $rsa = new Crypt_RSA();
    $rsa->loadKey($cert_info["pkey"], CRYPT_RSA_PRIVATE_FORMAT_PKCS1);
    $rsa->setHash('sha256');
    $rsa->setMGFHash('sha256');

    $ciphertext = base64_decode($login_step2->{'sessionKey'});
    $sessionKey = $rsa->decrypt($ciphertext);

    if ($debug) {
        echo base64_encode($sessionKey);
        echo ("\n");
    }

    $ciphertext = base64_decode($login_step2->{'validationKey'});
    $validationKey = $rsa->decrypt($ciphertext);

    if ($debug) {
        echo base64_encode($validationKey);
        echo ("\n");
    }

    $login_step3 = bea_login_step3($login_step2, $validationKey);
    if ((!is_string($login_step3)) && (isset($login_step3["error"]))){
        return $login_step3;
    }

    $res["token"] = $login_step3;
    $res["sessionKey"] = base64_encode($sessionKey);
    $res["safeId"] = $login_step2->{'safeId'};

    return $res;
}


function bea_login_step3($login_step2, $validationKey) {

    global $debug;

    $req3["tokenValidation"] = $login_step2->{'tokenValidation'};
    $req3["validationKey"] = base64_encode($validationKey);

    $func3 = 'bea_login_step3';
    $login_step3_json = send_request(json_encode($req3, JSON_UNESCAPED_SLASHES), $func3);

    $login_step3 = json_decode($login_step3_json);

    if (isset($login_step3->error)){
        return $login_step3;
    }

    if ($debug) {
        print $login_step3->{'token'};
        echo ("\n");
    }

    return $login_step3->{'token'};
}


function bea_check_session($token) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_check_session');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_get_postboxes($token) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_get_postboxes');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_get_folderoverview($token, $folderId, $sessionKey) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->folderId = $folderId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_get_folderoverview');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    // convert to array
    $array = json_decode($res, true);

    if (isset($array->error)){
        return $array;
    }

    if (isset($array["messages"])){
        //decSubject
        $nbre = count($array["messages"]);

        for ($i = 0; $i < $nbre; $i++) { // we do not use foreach since we add a new element to the current array

            $subject_to_decrypt = base64_decode($array["messages"][$i]["encSubject"]["value"]);
            $iv = base64_decode($array["messages"][$i]["encSubject"]["iv"]);
            $tag = base64_decode($array["messages"][$i]["encSubject"]["tag"]);

            if ($debug) {
                echo ("Element i=$i/nbre=$nbre\n");
                echo ('["encSubject"]["value"]=' . $array["messages"][$i]["encSubject"]["value"] . "\n");
                echo ('["encSubject"]["iv"]=' . $array["messages"][$i]["encSubject"]["iv"] . "\n");
                echo ('["encSubject"]["tag"]=' . $array["messages"][$i]["encSubject"]["tag"] . "\n");
            }

            while (openssl_error_string() !== false);
            $subject_decrypted = openssl_decrypt($subject_to_decrypt, 'aes-256-gcm', base64_decode($sessionKey), OPENSSL_RAW_DATA, $iv, $tag);
            if ($debug) while ($msg = openssl_error_string()) echo $msg . "\n";

            //insert decSubject in the array
            $array["messages"][$i]["decSubject"] = $subject_decrypted;
        }
    }

    return $array;
}


function bea_get_message($token, $messageId, $sessionKey) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->messageId = $messageId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_get_message');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    // convert to array
    $array = json_decode($res, true);

    if (isset($array->error)){
        return $array;
    }

    // get the subject
    $decSubject = '';

    if (isset($array["metaData"]))
        if (isset($array["metaData"]["subject"]))
            if (isset($array["metaData"]["subject"]["value"])) {

                $subject_to_decrypt = base64_decode($array["metaData"]["subject"]["value"]);
                $iv = base64_decode($array["metaData"]["subject"]["iv"]);
                $tag = base64_decode($array["metaData"]["subject"]["tag"]);

                if ($debug) {
                    echo ('["subject"]["value"]=' . $array["metaData"]["subject"]["value"] . "\n");
                    echo ('["subject"]["iv"]=' . $array["metaData"]["subject"]["iv"] . "\n");
                    echo ('["subject"]["tag"]=' . $array["metaData"]["subject"]["tag"] . "\n");
                }

                while (openssl_error_string() !== false);
                if (($iv == "") || ($tag == "") || ($subject_to_decrypt == "")) {
                    $decSubject = "";
                } else {
                    $decSubject = openssl_decrypt($subject_to_decrypt, 'aes-256-gcm', base64_decode($sessionKey), OPENSSL_RAW_DATA, $iv, $tag);
                }
                if ($debug) while ($msg = openssl_error_string()) echo $msg . "\n";

                $array["metaData"]["decSubject"] = $decSubject;
                unset($array["metaData"]["subject"]); // delete encrypted subject: we do not use it anymore

            } else {
                if ($debug) echo ("message has no subject\n");
            }

    // decrypt objects and attachements
    $decryptedObjects = array();
    $attachmentsKey = array();
    $decryptedAttachments = array();

    foreach ($array["encryptedObjects"] as $element) {

        $objectKey = "";
        $key_to_decrypt = base64_decode($element["encKeyInfo"]["encKey"]["value"]);
        $iv = base64_decode($element["encKeyInfo"]["encKey"]["iv"]);
        $tag = base64_decode($element["encKeyInfo"]["encKey"]["tag"]);

        if ($debug) {
            echo ('["encKey"]["value"]=' . $element["encKeyInfo"]["encKey"]["value"] . "\n");
            echo ('["encKey"]["iv"]=' . $element["encKeyInfo"]["encKey"]["iv"] . "\n");
            echo ('["encKey"]["tag"]=' . $element["encKeyInfo"]["encKey"]["tag"] . "\n");
        }

        while (openssl_error_string() !== false);
        $objectKey = openssl_decrypt($key_to_decrypt, 'aes-256-gcm', base64_decode($sessionKey), OPENSSL_RAW_DATA, $iv, $tag);
        if ($debug) while ($msg = openssl_error_string()) echo $msg . "\n";

        if ($objectKey == '') {
            echo ("objectKey is empty -> exit!\n");
            exit();
        }

        $data = '';

        //decrypt encryptedObject with objectKey
        if (($element["enc_data"] == "") || ($element["enc_tag"] == "")) {
            $data = decrypt_aes256cbc($element["enc_data"], base64_encode($objectKey));
        } else {
            $iv = base64_decode($element["enc_iv"]);
            $tag = base64_decode($element["enc_tag"]);
            $data = openssl_decrypt(base64_decode($element["enc_data"]), 'aes-256-gcm', $objectKey, OPENSSL_RAW_DATA, $iv, $tag);
        }

        $decryptedObjects[] = array("name" => $element["enc_name"], "data" => $data);

        if ($element["enc_name"] == 'project_coco') {

            $xmlDoc = simplexml_load_string_skip_ns($data);
            $xmlDoc_array = object2array($xmlDoc);

            $EncryptedData = $xmlDoc_array["EncryptedData"];
            if ($EncryptedData) {
                $nbre = count($EncryptedData);
                for ($i = 0; $i < $nbre; $i++) {
                    $attachmentsKey[$i]["name"] = $EncryptedData[$i]["CipherData"]["CipherReference"]["@attributes"]["URI"];
                    if (substr($attachmentsKey[$i]["name"], 0, 4) == "cid:") $attachmentsKey[$i]["name"] = substr($attachmentsKey[$i]["name"], 4);
                    $attachmentsKey[$i]["key"] = $EncryptedData[$i]["KeyInfo"]["MgmtData"];
                    if ($debug) echo ("i=$i name=" . $attachmentsKey[$i]["name"] . " key=" . $attachmentsKey[$i]["key"] . "\n");
                }
            }
        }
    }

    if (isset($array["attachments"]))
        if (count($array["attachments"]) > 0)
            foreach ($array["attachments"] as $element) {

                $att_key = "";

                $nbre = count($attachmentsKey);
                for ($i = 0; $i < $nbre; $i++) {
                    if ($attachmentsKey[$i]["name"] == $element["reference"]) {
                        $att_key = base64_decode($attachmentsKey[$i]["key"]);
                        break;
                    }
                }

                if (
                    ($element["symEncAlgorithm"] == "http://www.w3.org/2001/04/xmlenc#aes256-cbc")
                    ||  ($element["iv"] == "" && $element["tag"] == "")
                ) {
                    if ($att_key == "") {
                        $data = decrypt_aes256cbc($element["data"], $element["key"], $element["iv"]);
                    } else {
                        $data = decrypt_aes256cbc($element["data"], base64_decode($att_key), $element["iv"]);
                    }
                } else {
                    $iv = base64_decode($element["iv"]);
                    $tag = base64_decode($element["tag"]);
                    $data = openssl_decrypt(base64_decode($element["data"]), 'aes-256-gcm', $att_key, OPENSSL_RAW_DATA, $iv, $tag);
                }

                $decryptedAttachments[] = array(
                    "reference" => $element["reference"],
                    "data" => base64_encode($data),
                    "type" => $element["type"],
                    "sizeKB" => $element["sizeKB"],
                    "hashValue" => $element["hashValue"]
                );
            }

    // re-create the array as result to deliver
    $res_dec = array(
        "osciSubject" => $array["osciSubject"],
        "osciMessageId" => $array["osciMessageId"],
        "messageId" => $array["messageId"],
        "attachments" => $decryptedAttachments,
        "decryptedObjects" => $decryptedObjects,
        "metaData" => $array["metaData"],
        "newEGVPMessage" => $array["newEGVPMessage"],
        "version" => $array["version"],
        "symEncAlgorithm" => $array["symEncAlgorithm"],
        // add the token
        "token" => $array["token"]
    );

    return $res_dec;
}




function bea_get_folderstructure($token, $postboxSafeId) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->postboxSafeId = $postboxSafeId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_get_folderstructure');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_get_addressbook($token) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_get_addressbook');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_add_addressbookentry($token, $identitySafeId) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->identitySafeId = $identitySafeId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_add_addressbookentry');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_delete_addressbookentry($token, $addressbookEntrySafeId) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->addressbookEntrySafeId = $addressbookEntrySafeId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_delete_addressbookentry');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_get_identitydata($token) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_get_identitydata');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_get_username($token, $identitySafeId) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->identitySafeId = $identitySafeId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_get_username');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_get_messageconfig($token) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_get_messageconfig');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}

function bea_add_folder($token, $parentFolderId, $newFolderName) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->parentFolderId = $parentFolderId;
    $_r->newFolderName = $newFolderName;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_add_folder');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_remove_folder($token, $folderId) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->folderId = $folderId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_remove_folder');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}



function bea_move_messagetofolder($token, $messageId, $folderId) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->messageId = $messageId;
    $_r->folderId = $folderId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_move_messagetofolder');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_move_messagetotrash($token, $messageId) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->messageId = $messageId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_move_messagetotrash');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_restore_messagefromtrash($token, $messageId) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->messageId = $messageId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_restore_messagefromtrash');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_delete_message($token, $messageId) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->messageId = $messageId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_delete_message');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_search(
    $token,
    $identitySafeId = "",
    $identityStatus = "",
    $identityType = "",
    $identityUsername = "",
    $identityFirstname = "",
    $identitySurname = "",
    $identityPostalcode = "",
    $identityCity = "",
    $identityChamberType = "",
    $identityChamberMembershipId = "",
    $identityOfficeName = ""
) {

    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->identitySafeId = $identitySafeId;
    $_r->identityStatus = $identityStatus;
    $_r->identityType = $identityType;
    $_r->identityUsername = $identityUsername;
    $_r->identityFirstname = $identityFirstname;
    $_r->identitySurname = $identitySurname;
    $_r->identityPostalcode = $identityPostalcode;
    $_r->identityCity = $identityCity;
    $_r->identityChamberType = $identityChamberType;
    $_r->identityChamberMembershipId = $identityChamberMembershipId;
    $_r->identityOfficeName = $identityOfficeName;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_search');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}




function bea_init_message($token, $postboxSafeId, $msg_infos, $sessionKey) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->postboxSafeId = $postboxSafeId;
    $_r->msg_infos = $msg_infos;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_init_message');

    if ($debug) {
        echo ("bea_init_message:\n");
        print_r($res);
        echo ("\n");
    }

    $res_j = json_decode($res, true);

    if (isset($res_j["error"])){
        return $res_j;
    }

    $key_decrypted = openssl_decrypt(
        base64_decode($res_j["key"]["value"]),
        'aes-256-gcm',
        base64_decode($sessionKey),
        OPENSSL_RAW_DATA,
        base64_decode($res_j["key"]["iv"]),
        base64_decode($res_j["key"]["tag"])
    );
    if ($debug) while ($msg = openssl_error_string()) echo $msg . "\n";

    $dec_msg_struct = array(
        "messageToken" => $res_j["messageToken"],
        "key" => base64_encode($key_decrypted),
    );

    if ($debug) {
        echo ("dec_msg_struct:\n");
        print_r($dec_msg_struct);
        echo ("\n");
    }

    return $dec_msg_struct;
}



function encrypt_aes256gcm($input, $key) {
    $tag = "";
    $iv = openssl_random_pseudo_bytes(16); //openssl_cipher_iv_length("aes-256-gcm") returns 12!!!
    $encrypted = openssl_encrypt($input, "aes-256-gcm", base64_decode($key), $options = OPENSSL_RAW_DATA, $iv, $tag);
    
    return array(
        'data' => base64_encode($encrypted), 
        'tag' => base64_encode($tag), 
        'iv' => base64_encode($iv)
    );
}

function sha256_hash_bytes($b64_data) {
    $bytes = base64_decode($b64_data);
    $hash = hash('sha256', $bytes, true); // Hash the bytes
    return $hash;
}


function bea_encrypt_message($token, $postboxSafeId, $msg_infos, $msg_att, $sessionKey, $messageDraft = null) {
    global $debug;
    $new_message = null;

    if ($messageDraft == null) {
        $new_message = bea_init_message($token, $postboxSafeId, $msg_infos, $sessionKey);
    } else {
        $new_message["messageToken"] = $messageDraft["messageToken"];
        $new_message["key"] = $messageDraft["key"];
    }

    if (isset($new_message["error"])){
        return $new_message;
    }

    // create save/send message request
    $_r = new stdClass();
    $_r->messageToken = $new_message["messageToken"];
    $_r->msg_infos = $msg_infos;
    $_r->encrypted_data = new stdClass();

    // encrypt subject
    $enc_subject = encrypt_aes256gcm($msg_infos["betreff"], $new_message["key"]);
    $enc_subject["key"] = $new_message["key"];
    $_r->encrypted_data->encSubject = $enc_subject; // add to request

    if ($debug) {
        echo ("new_message:\n");
        print_r($new_message);
        echo ("\n");

        echo ("enc_subject:\n");
        print_r($enc_subject);
        echo ("\n");

        echo ("msg_att:\n");
        print_r($msg_att);
        echo ("\n");
    }

    //encrypt attachments
    $_r->encrypted_data->attachments = [];
    if (is_array($msg_att)) {
        foreach ($msg_att as $element) {
            echo("encrypt att -> "); print_r($element["name"]); echo ("\n");
            $enc_att = encrypt_aes256gcm(base64_decode($element["data"]), $new_message["key"]);

            $tmp_att = array(
                "name" => $element["name"],
                "iv" => $enc_att["iv"],
                "tag" => $enc_att["tag"],
                "data" => $enc_att["data"],
                "key" => $new_message["key"],
                "sizeKB" => intval(strlen($enc_att["data"]) / 1024),
                "hash" => base64_encode(sha256_hash_bytes($element["data"])),
                "att_type" => $element["att_type"]
            );

            array_push($_r->encrypted_data->attachments, $tmp_att);// add to request
        }
    }

    if ($debug) {
        echo ("encrypted attachments:\n");
        print_r($_r->encrypted_data->attachments);
        echo ("\n");

        echo ("request:\n");
        print_r($_r);
        print(json_encode($_r, JSON_UNESCAPED_SLASHES));
        echo ("\n");
    }

    //print_r($_r);
    return $_r;
}


function bea_save_message($token, $postboxSafeId, $msg_infos, $msg_att, $sessionKey, $messageDraft = null) {
    global $debug;

    $_r = bea_encrypt_message($token, $postboxSafeId, $msg_infos, $msg_att, $sessionKey, $messageDraft);
    if ((is_array($_r)) && (isset($_r["error"]))){
        return $_r;
    }

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_save_message');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}


function bea_send_message($token, $postboxSafeId, $msg_infos, $msg_att, $sessionKey, $messageDraft = null) {
    global $debug;

    $_r = bea_encrypt_message($token, $postboxSafeId, $msg_infos, $msg_att, $sessionKey, $messageDraft);
    if ((is_array($_r)) && (isset($_r["error"]))){
        return $_r;
    }

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_send_message');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return bea_send_message_validation($sessionKey, json_decode($res, true));
}


function bea_send_message_validation($sessionKey, $message_validations_enc) {
    global $debug;

    //decrypt validations
    $dec_validations = [];
    if (is_array($message_validations_enc["validations"])) {
        foreach ($message_validations_enc["validations"] as $element) {
            print_r($element);

            $dec_data = openssl_decrypt(
                base64_decode($element["data"]),
                'aes-256-gcm',
                base64_decode($sessionKey),
                OPENSSL_RAW_DATA,
                base64_decode($element["iv"]),
                base64_decode($element["tag"])
            );
            if ($debug) while ($msg = openssl_error_string()) echo $msg . "\n";

            $tmp_arr = array(
                "id" => $element["id"],
                "data" => $dec_data,
            );
            array_push($dec_validations, $tmp_arr);
        }
    }

    //print_r($dec_validations);


    $_r = new stdClass();
    $_r->validationTokenMSG = $message_validations_enc["validationTokenMSG"];
    $_r->validations = $dec_validations;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_send_message_validation');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    return json_decode($res, true);
}




function bea_init_message_draft($token, $messageId, $sessionKey) {
    global $debug;

    $_r = new stdClass();
    $_r->token = $token;
    $_r->messageId = $messageId;

    $res = send_request(json_encode($_r, JSON_UNESCAPED_SLASHES), 'bea_init_message_draft');

    if ($debug) {
        print_r($res);
        echo ("\n");
    }

    // convert to array
    $msg_draft = json_decode($res, true);

    // create message info structure
    $msg_infos = new stdClass();
    $msg_att = array();
    $res_dec = array();

    // decrypt subject and add it to the message info struct
    $decSubject = '';

    if (isset($msg_draft["msg_infos"])){
        $msg_infos->receivers = array();
        $msg_infos->attachments = array();
        
        if (isset($msg_draft["msg_infos"]["aktz_sender"])){
            $msg_infos->aktz_sender = $msg_draft["msg_infos"]["aktz_sender"];
        }else{
            $msg_infos->aktz_sender = "";
        }

        if (isset($msg_draft["msg_infos"]["aktz_rcv"])){
            $msg_infos->aktz_rcv = $msg_draft["msg_infos"]["aktz_rcv"];
        }else{
            $msg_infos->aktz_rcv = "";
        }

        if (isset($msg_draft["msg_infos"]["msg_text"])){
            $msg_infos->msg_text = $msg_draft["msg_infos"]["msg_text"];
        }else{
            $msg_infos->msg_text = "";
        }

        if (isset($msg_draft["msg_infos"]["is_eeb"])){
            $msg_infos->is_eeb = $msg_draft["msg_infos"]["is_eeb"];
        }else{
            $msg_infos->is_eeb = false;
        }

        if (isset($msg_draft["msg_infos"]["dringend"])){
            $msg_infos->dringend = $msg_draft["msg_infos"]["dringend"];
        }else{
            $msg_infos->dringend = false;
        }

        if (isset($msg_draft["msg_infos"]["pruefen"])){
            $msg_infos->pruefen = $msg_draft["msg_infos"]["pruefen"];
        }else{
            $msg_infos->pruefen = false;
        }

        if (isset($msg_draft["msg_infos"]["is_eeb_response"])){
            $msg_infos->is_eeb_response = $msg_draft["msg_infos"]["is_eeb_response"];
        }else{
            $msg_infos->is_eeb_response = false;
        }

        if (isset($msg_draft["msg_infos"]["eeb_fremdid"])){
            $msg_infos->eeb_fremdid = $msg_draft["msg_infos"]["eeb_fremdid"];
        }else{
            $msg_infos->eeb_fremdid = "";
        }

        if (isset($msg_draft["msg_infos"]["eeb_date"])){
            $msg_infos->eeb_date = $msg_draft["msg_infos"]["eeb_date"];
        }else{
            $msg_infos->eeb_date = "";
        }

        if (isset($msg_draft["msg_infos"]["verfahrensgegenstand"])){
            $msg_infos->verfahrensgegenstand = $msg_draft["msg_infos"]["verfahrensgegenstand"];
        }else{
            $msg_infos->verfahrensgegenstand = "";
        }

        if (isset($msg_draft["msg_infos"]["eeb_erforderlich"])){
            $msg_infos->eeb_erforderlich = $msg_draft["msg_infos"]["eeb_erforderlich"];
        }else{
            $msg_infos->eeb_erforderlich = false;
        }

        if (isset($msg_draft["msg_infos"]["eeb_accept"])){
            $msg_infos->eeb_accept = $msg_draft["msg_infos"]["eeb_accept"];
        }else{
            $msg_infos->eeb_accept = false;
        }

        if (isset($msg_draft["msg_infos"]["xj"])){
            $msg_infos->xj = $msg_draft["msg_infos"]["xj"];
        }else{
            $msg_infos->xj = true;
        }

        if (isset($msg_draft["msg_infos"]["nachrichten_typ"])){
            $msg_infos->nachrichten_typ = $msg_draft["msg_infos"]["nachrichten_typ"];
        }else{
            $msg_infos->nachrichten_typ = "";
        }

        if (isset($msg_draft["msg_infos"]["eeb_reject_code"])){
            $msg_infos->eeb_reject_code = $msg_draft["msg_infos"]["eeb_reject_code"];
        }else{
            $msg_infos->eeb_reject_code = "";
        }

        if (isset($msg_draft["msg_infos"]["eeb_reject_grund"])){
            $msg_infos->eeb_reject_grund = $msg_draft["msg_infos"]["eeb_reject_grund"];
        }else{
            $msg_infos->eeb_reject_grund = "";
        }

        if (isset($msg_draft["msg_infos"]["xj_version3"])){
            $msg_infos->xj_version3 = $msg_draft["msg_infos"]["xj_version3"];
        }else{
            $msg_infos->xj_version3 = true;
        }

        if (isset($msg_draft["msg_infos"]["gericht_code"])){
            $msg_infos->gericht_code = $msg_draft["msg_infos"]["gericht_code"];
        }else{
            $msg_infos->gericht_code = "";
        }

 

        if (isset($msg_draft["msg_infos"]["betreff"])){
            if (isset($msg_draft["msg_infos"]["betreff"]["value"])) {

                $subject_to_decrypt = base64_decode($msg_draft["msg_infos"]["betreff"]["value"]);
                $iv = base64_decode($msg_draft["msg_infos"]["betreff"]["iv"]);
                $tag = base64_decode($msg_draft["msg_infos"]["betreff"]["tag"]);

                if ($debug) {
                    echo ('["betreff"]["value"]=' . $msg_draft["msg_infos"]["betreff"]["value"] . "\n");
                    echo ('["betreff"]["iv"]=' . $msg_draft["msg_infos"]["betreff"]["iv"] . "\n");
                    echo ('["betreff"]["tag"]=' . $msg_draft["msg_infos"]["betreff"]["tag"] . "\n");
                }

                while (openssl_error_string() !== false);
                if (($iv == "") || ($tag == "") || ($subject_to_decrypt == "")) {
                    $decSubject = "";
                } else {
                    $decSubject = openssl_decrypt($subject_to_decrypt, 'aes-256-gcm', base64_decode($sessionKey), OPENSSL_RAW_DATA, $iv, $tag);
                }
                if ($debug) while ($msg = openssl_error_string()) echo $msg . "\n";

                $msg_draft["msg_infos"]["betreff"] = $decSubject;
                //unset($msg_draft["msg_infos"]["betreff"]); // delete encrypted subject: we do not use it anymore

            } else {
                if ($debug) echo ("message has no subject\n");
            } // end -> if (isset($msg_draft["msg_infos"]["betreff"]["value"])) / else
        } // if (isset($msg_draft["msg_infos"]["betreff"]))
    


        // get the receivers safeIds and add it to the message info struct
        if (isset($msg_draft["msg_infos"]["receivers"])){
            foreach ($msg_draft["msg_infos"]["receivers"] as $element) {
                if (isset($element["safeId"])){
                    array_push($msg_infos->receivers, $element["safeId"]);
                }
            }
        }


        // decrypt the encryptedObjects to get the Attachment keys
        $decryptedObjects = array();
        $attachmentsKey = array();

        if (isset($msg_draft["msg_infos"]["encryptedObjects"])){
            foreach ($msg_draft["msg_infos"]["encryptedObjects"] as $element) {
                $objectKey = "";
                $key_to_decrypt = base64_decode($element["encKeyInfo"]["encKey"]["value"]);
                $iv = base64_decode($element["encKeyInfo"]["encKey"]["iv"]);
                $tag = base64_decode($element["encKeyInfo"]["encKey"]["tag"]);

                if ($debug) {
                    echo ('["encKey"]["value"]=' . $element["encKeyInfo"]["encKey"]["value"] . "\n");
                    echo ('["encKey"]["iv"]=' . $element["encKeyInfo"]["encKey"]["iv"] . "\n");
                    echo ('["encKey"]["tag"]=' . $element["encKeyInfo"]["encKey"]["tag"] . "\n");
                }

                while (openssl_error_string() !== false);
                $objectKey = openssl_decrypt($key_to_decrypt, 'aes-256-gcm', base64_decode($sessionKey), OPENSSL_RAW_DATA, $iv, $tag);
                if ($debug) while ($msg = openssl_error_string()) echo $msg . "\n";

                if ($objectKey == '') {
                    echo ("objectKey is empty -> exit!\n");
                    exit();
                }

                $data = '';

                //decrypt encryptedObject with objectKey
                if (($element["enc_data"] == "") || ($element["enc_tag"] == "")) {
                    $data = decrypt_aes256cbc($element["enc_data"], base64_encode($objectKey));
                } else {
                    $iv = base64_decode($element["enc_iv"]);
                    $tag = base64_decode($element["enc_tag"]);
                    $data = openssl_decrypt(base64_decode($element["enc_data"]), 'aes-256-gcm', $objectKey, OPENSSL_RAW_DATA, $iv, $tag);
                }

                $decryptedObjects[] = array("name" => $element["enc_name"], "data" => $data);

                if ($element["enc_name"] == 'project_coco') {

                    $xmlDoc = simplexml_load_string_skip_ns($data);
                    $xmlDoc_array = object2array($xmlDoc);

                    $EncryptedData = $xmlDoc_array["EncryptedData"];
                    if ($EncryptedData) {
                        $nbre = count($EncryptedData);
                        for ($i = 0; $i < $nbre; $i++) {
                            $attachmentsKey[$i]["name"] = $EncryptedData[$i]["CipherData"]["CipherReference"]["@attributes"]["URI"];
                            if (substr($attachmentsKey[$i]["name"], 0, 4) == "cid:") $attachmentsKey[$i]["name"] = substr($attachmentsKey[$i]["name"], 4);
                            $attachmentsKey[$i]["key"] = $EncryptedData[$i]["KeyInfo"]["MgmtData"];
                            if ($debug) echo ("i=$i name=" . $attachmentsKey[$i]["name"] . " key=" . $attachmentsKey[$i]["key"] . "\n");
                        }
                    }
                }
            } // end  -> foreach ($msg_draft["msg_infos"]["encryptedObjects"] as $element)
        } // end -> if (isset($msg_draft["msg_infos"]["encryptedObjects"]))

        if ($debug) {
            echo ("decryptedObjects:\n");
            print_r($decryptedObjects);
            echo ("\n");

            echo ("attachmentsKey:\n");
            print_r($attachmentsKey);
            echo ("\n");
        }


        // get the attachments names and add it to the message info struct
        // and decrypt the attachments to add it into the msg_att struct
        $msg_key = "";
        if (isset($msg_draft["msg_infos"]["attachments"])){
            if (count($msg_draft["msg_infos"]["attachments"]) > 0){
                foreach ($msg_draft["msg_infos"]["attachments"] as $element) {
                    $att_key = "";

                    $nbre = count($attachmentsKey);
                    for ($i = 0; $i < $nbre; $i++) {
                        if ($attachmentsKey[$i]["name"] == $element["reference"]) {
                            $att_key = base64_decode($attachmentsKey[$i]["key"]);
                            break;
                        }
                    }

                    if (
                        ($element["symEncAlgorithm"] == "http://www.w3.org/2001/04/xmlenc#aes256-cbc")
                        ||  ($element["iv"] == "" && $element["tag"] == "")
                    ) {
                        if ($att_key == "") {
                            $data = decrypt_aes256cbc($element["data"], $element["key"], $element["iv"]);
                        } else {
                            $data = decrypt_aes256cbc($element["data"], base64_decode($att_key), $element["iv"]);
                        }
                    } else {
                        $iv = base64_decode($element["iv"]);
                        $tag = base64_decode($element["tag"]);
                        $data = openssl_decrypt(base64_decode($element["data"]), 'aes-256-gcm', $att_key, OPENSSL_RAW_DATA, $iv, $tag);
                    }

                    // append decrypted attachment to struct if not xjustiz_nachricht.xml
                    if ($element["reference"] == "xjustiz_nachricht.xml"){
                        // TODO: read xj and extract infos to fill msg_infos
                        if (file_exists("xjustiz.php")) {
                            include("xjustiz.php");
                        
                            $xj = extract_xj_values($data);
                            $msg_infos->is_eeb = $xj["is_eeb"];
                            $msg_infos->is_eeb_response = $xj["is_eeb_response"];
                            $msg_infos->eeb_fremdid = $xj["fremdeNachrichtenID"];
                            $msg_infos->verfahrensgegenstand = $xj["verfahrensgegenstand"];
                            $msg_infos->eeb_erforderlich = $xj["eeb_erforderlich"];
                            $msg_infos->gericht_code = $xj["gericht_code"];
                        }

                    }else if ($element["reference"] != "Nachrichtentext.pdf"){
                        $decryptedAttachment = array(
                            "name" => $element["reference"],
                            "data" => base64_encode($data),
                            "att_type" => $element["type"]
                        );

                        array_push($msg_infos->attachments, $element["reference"]); // save name in msg_infos
                        array_push($msg_att, $decryptedAttachment); // save data in msg_att
                    }


                    
                    $msg_key = base64_encode($att_key);
                } // end -> foreach ($msg_draft["attachments"] as $element)
            } // end -> if (count($msg_draft["attachments"]) > 0)
        } // end -> if (isset($msg_draft["attachments"]))

        if ($debug) {
            echo ("msg_att:\n");
            print_r($msg_att);
            echo ("\n");

            echo ("msg_infos:\n");
            print_r($msg_infos);
            echo ("\n");
        }

        // re-create the array as result to deliver
        $res_dec = array(
            "msg_infos" => $msg_infos,
            "msg_att" => $msg_att,
            "messageDraft" => array(
                "messageToken" => $msg_draft["messageToken"],
                "key" => $msg_key
            ),
        );

    }else{
        // re-create the array as result to deliver
        $res_dec = array(
            "error" => "..."
        );
    } // end -> if (isset($msg_draft["msg_infos"]))

    return $res_dec;
}
