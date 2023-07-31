<?php
    include('bex_api.php');
    set_time_limit(0); // enlarge time execution of php script self


    // ***************
    // start the login
    // ***************
    $res = bea_login($cert, $pin);
    echo("Ergebnis LOGIN:\n");
    print_r($res);
    echo("\n");
    $sessionkey = $res['sessionKey']; // we save the sessionkey
    $token = $res['token'];
    $safeId = $res['safeId'];

    
    // *****************
    // check get_gericht_codes
    // *****************    
    $res = bea_get_gericht_codes($token);
    echo("Ergebnis get_gericht_codes:\n");
    print_r($res);
    echo("\n");

    
    // *****************
    // check session
    // *****************    
    $res = bea_check_session($token);
    echo("Ergebnis check_session:\n");
    print_r($res);
    echo("\n");

    // *****************
    // get the postboxes
    // *****************    
    $res = bea_get_postboxes($token);
    echo("Ergebnis POSTBOXES:\n");
    print_r($res);
    echo("\n");

    //save postboxes for later
    $postboxes = $res;

    // get the SAFE-ID of the first postbox
    $postboxsafeid = $res["postboxes"][0]["postboxSafeId"];
    
    // look for INBOX
    $inboxid="";
    foreach($res["postboxes"][0]["folder"] as $val) {
        echo("FID:".$val["id"]." TYPE:".$val["type"]."\n");
        if($val["type"] == "INBOX") $inboxid = $val["id"];
    }

    if($inboxid == "") {
        echo "no inbox found -> exit!";
        exit;
    }


    // ********************
    // get the INBOX-folder
    // ********************    
    $res = bea_get_folderoverview($token, $inboxid, $sessionkey);
    echo("Ergebnis FOLDEROVERVIEW:\n");
    print_r($res);
    echo("\n");

    //save folderoverview for later
    $folderoverview = $res;

    // look for all messages in the INBOX and get the first one
    $firstmessageid = "";
    foreach($res["messages"] as $val) {        
        echo("messageId:".$val["messageId"]." zugegangen:".$val["zugegangen"]." decSubject:'".$val["decSubject"]."'\n");
        if($firstmessageid == "") $firstmessageid = $val["messageId"];
    }    

    if($firstmessageid == "") {
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
    $res = bea_get_message($token, $firstmessageid, $sessionkey);
    echo("Ergebnis GETMESSAGE:\n");
    print_r($res);
    echo("\n");



    // *****************
    // get folderstructure
    // *****************    
    $res = bea_get_folderstructure($token, $safeId);
    echo("Ergebnis FOLDERSTRUCTURE:\n");
    print_r($res);
    echo("\n");


    // *****************
    // get addressbook
    // *****************    
    $res = bea_get_addressbook($token);
    echo("Ergebnis ADDRESSBOOK:\n");
    print_r($res);
    echo("\n");


    // *****************
    // add addressbook entry
    // *****************    
    $res = bea_add_addressbookentry($token, $safeId);
    echo("Ergebnis ADD ADDRESSBOOK:\n");
    print_r($res);
    echo("\n");

    // *****************
    // delete addressbook entry
    // *****************    
    $res = bea_delete_addressbookentry($token, $safeId);
    echo("Ergebnis DEL ADDRESSBOOK:\n");
    print_r($res);
    echo("\n");


    // *****************
    // get identity data
    // *****************    
    $res = bea_get_identitydata($token);
    echo("Ergebnis bea_get_identitydata:\n");
    print_r($res);
    echo("\n");


    // *****************
    // get username
    // *****************    
    $res = bea_get_username($token, $safeId);
    echo("Ergebnis bea_get_username:\n");
    print_r($res);
    echo("\n");


    // *****************
    // get message config
    // *****************    
    $res = bea_get_messageconfig($token);
    echo("Ergebnis bea_get_messageconfig:\n");
    print_r($res);
    echo("\n");
    

    // *****************
    // add folder
    // *****************   
    $parentFolderId =  $postboxes["postboxes"][0]["folder"][0]["id"];
    $newFolderName = "PHP_new_folder";
    $res = bea_add_folder($token, $parentFolderId, $newFolderName);
    echo("Ergebnis bea_add_folder:\n");
    print_r($res);
    echo("\n");

    $folderid_added = $res["id"]; // folder to remove later


    // *****************
    // move message to folder
    // *****************   
    $messageId = $folderoverview["messages"][0]["messageId"];
    $res = bea_move_messagetofolder($token, $messageId, $folderid_added);
    echo("Ergebnis bea_move_messagetofolder:\n");
    print_r($res);
    echo("\n");


    // *****************
    // move message to trash
    // ***************** 
    $res = bea_move_messagetotrash($token, $messageId);
    echo("Ergebnis bea_move_messagetotrash:\n");
    print_r($res);
    echo("\n");


    // *****************
    // restore message from trash
    // ***************** 
    $res = bea_restore_messagefromtrash($token, $messageId);
    echo("Ergebnis bea_restore_messagefromtrash:\n");
    print_r($res);
    echo("\n");


    // *****************
    // move message to orginal folder (revert changes)
    // ***************** 
    $res = bea_move_messagetofolder($token, $messageId, $parentFolderId);
    echo("Ergebnis bea_move_messagetofolder:\n");
    print_r($res);
    echo("\n");


    // *****************
    // remove folder
    // *****************   
    $res = bea_remove_folder($token, $folderid_added);
    echo("Ergebnis bea_remove_folder:\n");
    print_r($res);
    echo("\n");


    // *****************
    // delete message
    // *****************   
    $res = bea_delete_message($token, $folderid_added);
    echo("Ergebnis bea_delete_message:\n");
    print_r($res);
    echo("\n");


    // *****************
    // remove search 1
    // *****************   
    $res = bea_search($token, "", "", "", "", "", "", "70619", "Stuttgart");
    echo("Ergebnis bea_search 1:\n");
    print_r($res);
    echo("\n");
    

    // *****************
    // remove search 2
    // *****************   
    $res = bea_search($token, "", "", "", "", "", "", "70619", "Stuttgartä");
    echo("Ergebnis bea_search 2:\n");
    print_r($res);
    echo("\n");




    /*
     * send, save message
     */


    // *****************
    // init message
    // *****************   
    $msg_infos = array(
        "betreff" => "PHP init message",
        "aktz_sender" => "PHP aktz_sender",
        "aktz_rcv" => "PHP aktz_rcv",
        "msg_text" => "This is a test message sent from PHP.",
        "is_eeb" => false,
        "dringend" => false,
        "pruefen" => false,
        "receivers" => array(),
        "attachments" => array(),
        "is_eeb_response" => false,
        "eeb_fremdid" => "",
        "eeb_date" => "",
        "verfahrensgegenstand" => "",
        "eeb_erforderlich" => false,
        "eeb_accept" => false,
        "xj" => true,
        "nachrichten_typ" => "ALLGEMEINE_NACHRICHT",
        "eeb_reject_code" => "",
        "eeb_reject_grund" => "",
        "xj_version3" => true,
        "gericht_code" => ""
    );

    array_push($msg_infos["receivers"], "DE.Justiztest.dd380ae8-10f8-4b5f-8dce-e54b80722409.a80d");
    array_push($msg_infos["attachments"], "01_myText.txt");

    $tmp_att = array(
        "name" => "01_myText.txt",
        "data" => "TXkgdGV4dCAx",
        "att_type" => "SCHRIFTSATZ"
    );

    $msg_att = array();
    array_push($msg_att, $tmp_att);
    //print_r($msg_att);

    /*
        create a draft message with the given informations & attachments
    */
    $res = bea_save_message($token, $safeId, $msg_infos, $msg_att, $sessionkey);
    echo("Ergebnis bea_save_message:\n");
    print_r($res);
    echo("\n");


    /*
        send a message with the given informations & attachments
    */
    $res = bea_send_message($token, $safeId, $msg_infos, $msg_att, $sessionkey);
    echo("Ergebnis bea_send_message:\n");
    print_r($res);
    echo("\n");








    /*
     * init message, save draft, init draft, edit message, send (or save) message
     */
        // *****************
    // init message
    // *****************   
    $msg_infos = array(
        "betreff" => "PHP init message",
        "aktz_sender" => "PHP aktz_sender",
        "aktz_rcv" => "PHP aktz_rcv",
        "msg_text" => "This is a test message sent from PHP.",
        "is_eeb" => false,
        "dringend" => false,
        "pruefen" => false,
        "receivers" => ["DE.Justiztest.dd380ae8-10f8-4b5f-8dce-e54b80722409.a80d"],
        "attachments" => ["01_myText.txt"],
        "is_eeb_response" => false,
        "eeb_fremdid" => "",
        "eeb_date" => "",
        "verfahrensgegenstand" => "",
        "eeb_erforderlich" => false,
        "eeb_accept" => false,
        "xj" => true,
        "nachrichten_typ" => "ALLGEMEINE_NACHRICHT",
        "eeb_reject_code" => "",
        "eeb_reject_grund" => "",
        "xj_version3" => true,
        "gericht_code" => ""
    );

    $msg_att = [
        array(
            "name" => "01_myText.txt",
            "data" => "TXkgdGV4dCAx",
            "att_type" => "SCHRIFTSATZ"
        )
    ];


    /*
        create a draft message with the given informations & attachments
    */
    $res = bea_save_message($token, $safeId, $msg_infos, $msg_att, $sessionkey);
    echo("Ergebnis bea_save_message:\n");
    print_r($res);
    echo("\n");


    /*
        get the draft message, modify it and send (or save) it
    */
    $messageId = $res['messageId'];
    $res = bea_init_message_draft($token, $messageId, $sessionkey);
    echo("Ergebnis bea_init_message_draft:\n");
    print_r($res);
    echo("\n");

    $msg_infos_draft = $res["msg_infos"];
    $msg_att_draft = $res["msg_att"];
    $messageDraft = $res["messageDraft"];

    // edit darft infos
    $msg_infos_draft->betreff = "PHP edit draft message";
    $msg_infos_draft->msg_text = "My new text PHP";
    
    // add new attachment
    $msg_new_attachment = array(
        "name" => "02_myText.txt",
        "data" => "TXkgdGV4dCAy",
        "att_type" => ""
    );
    array_push($msg_att_draft, $msg_new_attachment);
    array_push($msg_infos_draft->attachments, "02_myText.txt");

    // convert stdClass to an array
    $msg_infos = json_decode(json_encode($msg_infos_draft), true);

    // values for send/safe message based on draft
    echo("msg_att_draft:\n"); print_r($msg_att_draft);
    echo("msg_infos (as array):\n"); print_r($msg_infos);
    echo("messageDraft:\n"); print_r($messageDraft);

    /*
        send the draft message with the given informations & attachments
    */
    $res = bea_send_message($token, $safeId, $msg_infos, $msg_att_draft, $sessionkey, $messageDraft);
    echo("Ergebnis bea_send_message:\n");
    print_r($res);
    echo("\n");
?>