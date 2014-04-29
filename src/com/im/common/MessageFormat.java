package com.im.common;

import com.google.gson.Gson;
import org.bouncycastle.util.encoders.Base64;
import org.json.simple.JSONObject;

import java.util.HashMap;

/**
 * Created by adityarao on 30/03/14.
 */
public class MessageFormat implements Messages {

    public String set_Fail (String message) {
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "Error");
        jsonObject.put("status", message);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_login_1(byte[] usernameEncrypted) {
        HashMap<String, byte[]> data = new HashMap<String, byte[]>();
        data.put("usernameEncrypted", usernameEncrypted);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "LOGIN");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_login_2(byte[] sessionToken, byte[] usernameSalt, byte[] DHServer, byte[] signature) {

        HashMap<String, byte[]> data = new HashMap<String, byte[]>();
        data.put("cookie", sessionToken);
        data.put("salt", usernameSalt);
        data.put("DH_Server", DHServer);
        data.put("Signature", signature);
        data.put("random", new Base64().encode("Hellow World".getBytes()));
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "login_2");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_Auth_Request(byte[] encryptedAuthToken, byte[] sessionToken, byte[] encryptedDHClient) {
        HashMap<String, byte[]> data = new HashMap<String, byte[]>();
        data.put("cookie", sessionToken);
        data.put("Encrypted Credentials", encryptedAuthToken);
        data.put("Encrypted Client DH", encryptedDHClient);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "set_Auth_Request");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_Auth_Response(byte[] encryptedClientGrant) {
        HashMap<String, byte[]> data = new HashMap<String, byte[]>();
        data.put("Encrypted Auth Response", encryptedClientGrant);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "set_Auth_Response");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_List_Request(byte[] encryptedChallenge) {
        HashMap<String, byte[]> data = new HashMap<String, byte[]>();
        data.put("nonce", encryptedChallenge);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "LIST");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_List_Response(byte[] encyrptedListResponse) {
        HashMap<String, byte[]> data = new HashMap<String, byte[]>();
        data.put("Encrypted List", encyrptedListResponse);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "List_Response");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_Talk_Request(byte[] encyptedTalkTo) {
        HashMap<String, byte[]> data = new HashMap<String, byte[]>();
        data.put("Encrypted Talk Request", encyptedTalkTo);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "TALK");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_Talk_Response(byte[] TGT, byte[] hmac, byte[] chatGrant) {
        HashMap<String, byte[]> data = new HashMap<String, byte[]>();
        data.put("TGT", TGT);
        data.put("HMAC", hmac);
        data.put("Chat_Grant", chatGrant);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "Talk_Response");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public byte[] set_Initiate_Chat_Request(byte[] ticket, byte[] key, byte[] iv, byte[] signedChallenge) throws Exception{
        HashMap<String, byte[]> messageToSend = new HashMap<String, byte[]>();
        messageToSend.put("Ticket", ticket);
        messageToSend.put("Session", key);
        messageToSend.put("IV", iv);
        messageToSend.put("Signature", signedChallenge);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "Talk_Request");
        jsonObject.put("data", messageToSend);
        Gson gson = new Gson();
        return (gson.toJson(jsonObject)).getBytes("UTF-8");
    }

    @Override
    public String set_Initiate_Chat_Response(byte[] encryptedResponse) {
        HashMap<String, byte[]> data = new HashMap<String, byte[]>();
        data.put("Encrypted Response", encryptedResponse);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "Talk_Response");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_Connection_Success(byte[] encrypted_success) {
        HashMap<String, byte[]> data = new HashMap<>();
        data.put("Encrypted_nonces", encrypted_success);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "Talk_Success");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_Chat_Message(byte[] encryptedChat) {
        HashMap<String, byte[]> data = new HashMap<>();
        data.put("Chat_and_nonce", encryptedChat);
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("type", "Message");
        jsonObject.put("data", data);
        Gson gson = new Gson();
        return gson.toJson(jsonObject);
    }

    @Override
    public String set_disconnect_request(byte[] encryptedChallenge) {
        return null;
    }

    @Override
    public String set_disconnect_response(byte[] encryptedChallenge) {
        return null;
    }

    @Override
    public String set_logout_request(byte[] encryptedChallenge) {
        return null;
    }

    @Override
    public String set_logout_response(byte[] encryptedChallenge) {
        return null;
    }

    @Override
    public Fields get_fields(String json) {
        Gson gson = new Gson();
        return gson.fromJson(json, Fields.class);
    }
}
