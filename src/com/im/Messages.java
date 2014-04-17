package com.im;

/**
 * Created by adityarao on 30/03/14.
 */
public interface Messages {
    public String set_login_1(byte[] usernameEncrypted);
    public String set_login_2(byte[] sessionToken, byte[] usernameSalt, byte[] encryptedDHServer, byte[] signature);
    public String set_Auth_Request(byte[] encryptedAuthToken, byte[] sessionToken, byte[] encryptedDHClient);
    public String set_Auth_Response(byte[] encryptedClientGrant);
    public String set_List_Request(byte[] encryptedChallenge);
    public String set_List_Response(byte[] encyrptedList);
    public String set_Talk_Request(byte[] encyptedTalkTo);
    public String set_Talk_Response(byte[] TGT, byte[] hmac, byte[] chatGrant);
    public byte[] set_Initiate_Chat_Request(byte[] TGT, byte[] key, byte[] iv, byte[] signedChallenge) throws Exception;
    public String set_Initiate_Chat_Response(byte[] encryptedChallenge);
    public String set_Connection_Success(byte[] nonce_encrypted);
    public String set_Chat_Message(byte[] encryptedChat);
    public String set_disconnect_request(byte[] encryptedChallenge);
    public String set_disconnect_response(byte[] encryptedChallenge);
    public String set_logout_request(byte[] encryptedChallenge);
    public String set_logout_response(byte[] encryptedChallenge);

    public Fields get_fields(String json);
}
