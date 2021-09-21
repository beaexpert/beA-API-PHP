<?php

    /* **********************
    beA.expert BEA-API / EXPERIMENTAL
    ---------------------------------
    Demo script not intented for production
    Version 1.1 / 09.09.2021
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

    $debug=false;

    if(file_exists("api.config.php")) {
        include("api.config.php"); // not public: bex_indent, cert etc ... only for beA.expert internal test
    } else {

        $bex_ident = "......"; // to be completeted
        $api_uri = "https://......."; // to be completed
        $cert = 'c:\\token.p12'; // to be completed
        $pin = '123456'; // to be completed

    }


    function send_request($__req, $__func){        

        global $bex_ident;
        global $api_uri;
        global $debug;

        $curl_session = curl_init();
        curl_setopt($curl_session, CURLOPT_URL, $api_uri.$__func);
        curl_setopt($curl_session, CURLOPT_RETURNTRANSFER, TRUE);
        curl_setopt($curl_session, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($curl_session, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($curl_session, CURLOPT_POST, true);
        curl_setopt($curl_session, CURLOPT_CUSTOMREQUEST, "POST");
        curl_setopt($curl_session, CURLOPT_POSTFIELDS, 'j='.base64_encode($__req));
        curl_setopt($curl_session, CURLOPT_HTTPHEADER, array(
                'Content-type: application/x-www-form-urlencoded',
                'bex-ident: '.$bex_ident)
        );

        if($debug) {
            $fp = fopen(dirname(__FILE__).'/api.curl.log', 'a');
            curl_setopt($curl_session, CURLOPT_VERBOSE, 1);
            curl_setopt($curl_session, CURLOPT_STDERR, $fp);
        }

        $result = curl_exec($curl_session);
        curl_close($curl_session );

        if($debug) {
            echo("result CURL:\n");
            print_r($result."\n");
        }

        return $result;
    }


    function get_cert_file_values($file, $pass=''){

        global $debug;

        if (!$cert_store = file_get_contents($file)) {
            echo "Fehler: Die Datei kann nicht geöffnet werden\n";
            exit;
        }
        
        if (openssl_pkcs12_read($cert_store, $cert_info, $pass)) {

            if($debug) {
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

        if($encrypted=='') {
            echo "decrypt_aes256cbc: no data to decode\n"; 
            return '';
        }
        
        if($iv==''){
            $iv=substr(base64_decode($encrypted),0,16);
            $encrypted=substr(base64_decode($encrypted),16);
        } else {
            $iv=base64_decode($iv);
            $encrypted=base64_decode($encrypted);
        }

        $decrypted='';
        $tag="";

        if($debug) {
            echo("decrypt_aes256cbc:encrypted:$encrypted\n");
            echo("decrypt_aes256cbc:key:$key\n");
            echo("decrypt_aes256cbc:iv:$iv\n");
        }
        
        while(openssl_error_string() !== false);
        $decrypted=openssl_decrypt($encrypted, 'aes-256-cbc', base64_decode($key), OPENSSL_RAW_DATA ,$iv, $tag);
        if($debug) while ($msg = openssl_error_string()) echo $msg."\n";
        
        return $decrypted;
    }


    function object2array($object) { return @json_decode(@json_encode($object),1); } 


    function simplexml_load_string_skip_ns($xml_string) {
        if(false === ($x1 = simplexml_load_string($xml_string)) ) return false;
        
        $namespaces = array_keys($x1->getDocNamespaces(true));
        $namespaces = array_filter($namespaces, function($k){return !empty($k);});
        $namespaces = array_map(function($ns){return "$ns:";}, $namespaces);
        
        return simplexml_load_string($ns_clean_xml = str_replace(
          array_merge(["xmlns="], $namespaces),
          array_merge(["ns="], array_fill(0, count($namespaces), '')),
          $xml_string
        ));
    }


    function bea_login($cert_file, $cert_pin){

        global $debug;

        $cert_info = get_cert_file_values($cert_file, $cert_pin);
        $thumprint = openssl_x509_fingerprint($cert_info["cert"], 'sha1', false);

        if($debug) echo("bea_login thumprint: $thumprint\n");
        
        $req["thumbprint"] = $thumprint;
        $login_step1_json = send_request(json_encode($req), 'bea_login_step1');

        $login_step1 = json_decode($login_step1_json);
        if($debug) {
            print $login_step1->{'challengeVal'};
            echo("\n");
            print $login_step1->{'challengeValidation'};
            echo("\n");
        }

        if (!openssl_sign(base64_decode($login_step1->{'challengeVal'}), $challenge_signed, $cert_info["pkey"], OPENSSL_ALGO_SHA256)){
            echo "Fehler: challengeVal kann nicht signiert werden.\n";
            exit;
        }

        if (!openssl_sign(base64_decode($login_step1->{'challengeValidation'}), $validation_signed, $cert_info["pkey"], OPENSSL_ALGO_SHA256)){
            echo "Fehler: challengeValidation kann nicht signiert werden.\n";
            exit;
        }

        return bea_login_step2($login_step1, $cert_info, $challenge_signed, $validation_signed);
    }


    function bea_login_step2($login_step1, $cert_info, $challenge_signed, $validation_signed){

        global $debug;

        $req2["tokenPAOS"] = $login_step1->{'tokenPAOS'};
        $req2["userCert"] = base64_encode($cert_info["cert"]);
        $req2["challengeSigned"] = base64_encode($challenge_signed);
        $req2["validationSigned"] = base64_encode($validation_signed);
        
        $func2 = 'bea_login_step2';
        $login_step2_json = send_request(json_encode($req2), $func2);
    
        $login_step2 = json_decode($login_step2_json);

        if($debug) {
            print $login_step2->{'sessionKey'};
            echo("\n");
            print $login_step2->{'validationKey'};
            echo("\n");
        }
    
        $rsa = new Crypt_RSA();
        $rsa->loadKey($cert_info["pkey"], CRYPT_RSA_PRIVATE_FORMAT_PKCS1);
        $rsa->setHash('sha256');
        $rsa->setMGFHash('sha256');
    
        $ciphertext = base64_decode($login_step2->{'sessionKey'});
        $sessionKey = $rsa->decrypt($ciphertext);

        if($debug) {        
            echo base64_encode($sessionKey);
            echo("\n");
        }
    
        $ciphertext = base64_decode($login_step2->{'validationKey'});
        $validationKey = $rsa->decrypt($ciphertext);

        if($debug) {
            echo base64_encode($validationKey);
            echo("\n");
        }

        $res["token"] = bea_login_step3($login_step2, $validationKey);
        $res["sessionKey"] = base64_encode($sessionKey);

        return $res;
    }


    function bea_login_step3($login_step2, $validationKey){

        global $debug;

        $req3["tokenValidation"] = $login_step2->{'tokenValidation'};
        $req3["validationKey"] = base64_encode($validationKey);
        
        $func3 = 'bea_login_step3';
        $login_step3_json = send_request(json_encode($req3), $func3);    

        $login_step3 = json_decode($login_step3_json);

        if($debug) {
            print $login_step3->{'token'};
            echo("\n");
        }

        return $login_step3->{'token'};
    }


    function bea_get_postboxes($token) {

        global $debug;

        $func = 'bea_get_postboxes';
        $req = '{"token" : "'.$token.'"}';
        $res = send_request($req, $func);

        if($debug) {
            print_r($res);
            echo("\n");
        }

        // convert to array
        $array=json_decode($res, true);

        return $array;
    }

    function bea_get_folderoverview($token,$folderId,$sessionKey) {

        global $debug;

        $func = 'bea_get_folderoverview';
        $req = '{"token":"'.$token.'","folderId":"'.$folderId.'"}';
        $res = send_request($req, $func);

        if($debug) {
            print_r($res);
            echo("\n");
        }

        // convert to array
        $array=json_decode($res, true);

        //decSubject
        $nbre=count($array["messages"]);

        for($i=0;$i<$nbre;$i++) { // we do not use foreach since we add a new element to the current array

            $subject_to_decrypt=base64_decode($array["messages"][$i]["encSubject"]["value"]);
            $iv=base64_decode($array["messages"][$i]["encSubject"]["iv"]);
            $tag=base64_decode($array["messages"][$i]["encSubject"]["tag"]);

            if($debug) {
                echo("Element i=$i/nbre=$nbre\n");
                echo('["encSubject"]["value"]='.$array["messages"][$i]["encSubject"]["value"]."\n");
                echo('["encSubject"]["iv"]='.$array["messages"][$i]["encSubject"]["iv"]."\n");
                echo('["encSubject"]["tag"]='.$array["messages"][$i]["encSubject"]["tag"]."\n");
            }
            
            while(openssl_error_string() !== false);
            $subject_decrypted=openssl_decrypt($subject_to_decrypt, 'aes-256-gcm', base64_decode($sessionKey), OPENSSL_RAW_DATA ,$iv,$tag);
            if($debug) while ($msg = openssl_error_string()) echo $msg."\n";

            //insert decSubject in the array
            $array["messages"][$i]["decSubject"]=$subject_decrypted;

        }

        return $array;
    }


    function bea_get_message($token, $messageId, $sessionKey) {

        global $debug;

        $func = 'bea_get_message';
        $req = '{"token":"'.$token.'","messageId":"'.$messageId.'"}';
        $res = send_request($req, $func);
      
        if($debug) {
            print_r($res);
            echo("\n");
        }

        // convert to array
        $array=json_decode($res, true);

        // get the subject
        $decSubject='';

        if(isset($array["metaData"]))
        if(isset($array["metaData"]["subject"]))
        if(isset($array["metaData"]["subject"]["value"])) {

            $subject_to_decrypt=base64_decode($array["metaData"]["subject"]["value"]);
            $iv=base64_decode($array["metaData"]["subject"]["iv"]);
            $tag=base64_decode($array["metaData"]["subject"]["tag"]);

            if($debug) {                
                echo('["subject"]["value"]='.$array["metaData"]["subject"]["value"]."\n");
                echo('["subject"]["iv"]='.$array["metaData"]["subject"]["iv"]."\n");
                echo('["subject"]["tag"]='.$array["metaData"]["subject"]["tag"]."\n");
            }
            
            while(openssl_error_string() !== false);
            if(($iv=="")||($tag=="")||($subject_to_decrypt=="")) {
                $decSubject="";
            } else {
                $decSubject=openssl_decrypt($subject_to_decrypt, 'aes-256-gcm', base64_decode($sessionKey), OPENSSL_RAW_DATA ,$iv,$tag);
            }
            if($debug) while ($msg = openssl_error_string()) echo $msg."\n";

            $array["metaData"]["decSubject"]=$decSubject;
            unset($array["metaData"]["subject"]); // delete encrypted subject: we do not use it anymore

        } else {
            if($debug) echo("message has no subject\n");
        }
        
        // decrypt objects and attachements
        $decryptedObjects=array();
        $attachmentsKey=array();
        $decryptedAttachments=array();

        foreach($array["encryptedObjects"] as $element) {

            $objectKey="";
            $key_to_decrypt=base64_decode($element["encKeyInfo"]["encKey"]["value"]);
            $iv=base64_decode($element["encKeyInfo"]["encKey"]["iv"]);
            $tag=base64_decode($element["encKeyInfo"]["encKey"]["tag"]);

            if($debug) {                
                echo('["encKey"]["value"]='.$element["encKeyInfo"]["encKey"]["value"]."\n");
                echo('["encKey"]["iv"]='.$element["encKeyInfo"]["encKey"]["iv"]."\n");
                echo('["encKey"]["tag"]='.$element["encKeyInfo"]["encKey"]["tag"]."\n");
            }

            while(openssl_error_string() !== false);
            $objectKey=openssl_decrypt($key_to_decrypt, 'aes-256-gcm', base64_decode($sessionKey), OPENSSL_RAW_DATA ,$iv,$tag);
            if($debug) while ($msg = openssl_error_string()) echo $msg."\n";

            if($objectKey=='') {
                echo("objectKey is empty -> exit!\n");
                exit();
            }

            $data='';

            //decrypt encryptedObject with objectKey
            if(($element["enc_data"]=="") || ($element["enc_tag"]=="")) {
                $data=decrypt_aes256cbc($element["enc_data"],base64_encode($objectKey));
            } else {
                $iv=base64_decode($element["enc_iv"]);
                $tag=base64_decode($element["enc_tag"]);                
                $data=openssl_decrypt(base64_decode($element["enc_data"]), 'aes-256-gcm', $objectKey, OPENSSL_RAW_DATA ,$iv, $tag);
            }

            $decryptedObjects[]=array("name"=>$element["enc_name"],"data"=>$data);

            if($element["enc_name"]=='project_coco') {                
            
                $xmlDoc=simplexml_load_string_skip_ns($data);
                $xmlDoc_array=object2array($xmlDoc);

                $EncryptedData=$xmlDoc_array["EncryptedData"];
                if($EncryptedData) {
                    $nbre=count($EncryptedData);
                    for($i=0;$i<$nbre;$i++) {        
                        $attachmentsKey[$i]["name"]=$EncryptedData[$i]["CipherData"]["CipherReference"]["@attributes"]["URI"];
                        if(substr($attachmentsKey[$i]["name"],0,4)=="cid:") $attachmentsKey[$i]["name"]=substr($attachmentsKey[$i]["name"],4);
                        $attachmentsKey[$i]["key"]=$EncryptedData[$i]["KeyInfo"]["MgmtData"];
                        if($debug)echo("i=$i name=".$attachmentsKey[$i]["name"]." key=".$attachmentsKey[$i]["key"]."\n");
                    }
                }

            }

        }

        if(isset($array["attachments"]))
        if(count($array["attachments"])>0)
        foreach($array["attachments"] as $element) {

            $att_key="";

            $nbre=count($attachmentsKey);
            for($i=0; $i<$nbre; $i++){
                if($attachmentsKey[$i]["name"]==$element["reference"]){
                    $att_key=base64_decode($attachmentsKey[$i]["key"]);                    
                    break;
                }
            }

            if(
                    ($element["symEncAlgorithm"]=="http://www.w3.org/2001/04/xmlenc#aes256-cbc")
                ||  ($element["iv"]=="" && $element["tag"]=="") 
            ) 
            {
                if($att_key=="") {
                    $data=decrypt_aes256cbc($element["data"], $element["key"], $element["iv"]);
                } else {
                    $data=decrypt_aes256cbc($element["data"], base64_decode($att_key), $element["iv"]);
                }

            } else {
                $iv=base64_decode($element["iv"]);
                $tag=base64_decode($element["tag"]); 
                $data=openssl_decrypt(base64_decode($element["data"]), 'aes-256-gcm', $att_key, OPENSSL_RAW_DATA ,$iv, $tag);
            }

            $decryptedAttachments[]=array(
                "reference"=>$element["reference"],
                "data"=>base64_encode($data),
                "type"=>$element["type"],
                "sizeKB"=>$element["sizeKB"],
                "hashValue"=>$element["hashValue"]
            );

        }

        // re-create the array as result to deliver
        $res_dec = array( 
            "osciSubject"=>$array["osciSubject"],
            "osciMessageId"=>$array["osciMessageId"],
            "messageId"=>$array["messageId"],
            "attachments"=>$decryptedAttachments,
            "decryptedObjects"=>$decryptedObjects,
            "metaData"=>$array["metaData"],
            "newEGVPMessage"=>$array["newEGVPMessage"],
            "version"=>$array["version"],
            "symEncAlgorithm"=>$array["symEncAlgorithm"],
            // add the token
            "token"=>$array["token"]
        );

        return $res_dec;
    }







    // ***************
    // start the login
    // ***************
    $res=bea_login($cert, $pin);
    echo("Ergebnis LOGIN:\n");
    print_r($res);
    echo("\n");
    $sessionkey=$res['sessionKey']; // we save the sessionkey
    $token=$res['token'];
    

    // *****************
    // get the postboxes
    // *****************    
    $res=bea_get_postboxes($token);
    echo("Ergebnis POSTBOXES:\n");
    print_r($res);
    echo("\n");

    // get the SAFE-ID of the first postbox
    $postboxsafeid=$res["postboxes"][0]["postboxSafeId"];
    
    // look for INBOX
    $inboxid="";
    foreach($res["postboxes"][0]["folder"] as $val) {
        echo("FID:".$val["id"]." TYPE:".$val["type"]."\n");
        if($val["type"]=="INBOX") $inboxid=$val["id"];
    }

    if($inboxid=="") {
        echo "no inbox found -> exit!";
        exit;
    }


    // ********************
    // get the INBOX-folder
    // ********************    
    $res=bea_get_folderoverview($token,$inboxid,$sessionkey);
    echo("Ergebnis FOLDEROVERVIEW:\n");
    print_r($res);
    echo("\n");

    // look for all messages in the INBOX and get the first one
    $firstmessageid="";
    foreach($res["messages"] as $val) {        
        echo("messageId:".$val["messageId"]." zugegangen:".$val["zugegangen"]." decSubject:'".$val["decSubject"]."'\n");
        if($firstmessageid=="") $firstmessageid=$val["messageId"];
    }    

    if($firstmessageid=="") {
        echo "no message found -> exit!";
        exit;
    }

    // force to use certain messages to test
    // $firstmessageid="1361276"; // good message with attachements (sent via beA SUITE PC)
    // $firstmessageid="1310240"; // new empty message
    // $firstmessageid="1310096"; // Hambuger-Message
    // $firstmessageid="1360988";

    echo("This is the messageId $firstmessageid of the message that we want to fetch ...\n");


    // ***********************
    // fetch the first message
    // ***********************
    $res=bea_get_message($token,$firstmessageid,$sessionkey);
    echo("Ergebnis GETMESSAGE:\n");
    print_r($res);
    echo("\n");    
?>
