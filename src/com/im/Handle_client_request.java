package com.im; /**
 * Created by Yogesh on 3/28/2014.
 */

import org.bouncycastle.util.encoders.Base64;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;

//import oracle.jrockit.jfr.settings.JSONElement;

public class Handle_client_request implements Runnable{

    Socket clientSocket;
    BufferedReader inStream;
    PrintWriter outStream;
    Server server;
    CryptoDHProvider serverDH;
    PublicKey publicKey;
    HelperFunc help;
    MessageFormat msgF;
    CryptoAESProvider aes;
    String user;

    public Handle_client_request(Socket pClientSocket, Server server){
        System.out.println("Initializing Login Thread");
        this.clientSocket = pClientSocket;
        this.server = server;
        try {
            inStream = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            outStream = new PrintWriter(clientSocket.getOutputStream(), true);
            this.serverDH = new CryptoDHProvider(false);
            msgF = new MessageFormat();
            help = new HelperFunc();
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error in Handle_client_request constructor");
        }
    }


    protected byte[] calculateCookie(Socket sock,byte[] n) {
        try {
            //Get the ip address of the user
            byte[] ip = sock.getInetAddress().getAddress();
            //byte[] nBytes = String.valueOf(n).getBytes();
            byte[] cat = HelperFunc.concatenateArrays(ip, n);

            //Calculate the hash (cookie)
            byte[] ret = MessageDigest.getInstance("SHA-256").digest(cat);

            return ret;
        }
        catch(Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    protected String getUsername(byte[] username)
    {
        /**
         * Decrypt the username with public key of server and return
         */
        String name=null;
        try {
            name = new String(server.serverRSA.decryptText(username));
        } catch (Exception e) {
            e.printStackTrace();
        }
        return name;
    }
    //Function to generate ticket for Talk Request
    public byte[] get_ticket(PublicKey pbk,InetAddress address, int port,
                             String username,byte[] timestamp,byte[] nonce,CryptoAESProvider aes)
    {
        byte[] pbk_bytes = pbk.getEncoded();
        byte[] addreBytes = address.getAddress();
        byte[] portBytes = ByteBuffer.allocate(4).putInt(port).array();
        byte[] userBytes = username.getBytes();
        ArrayList<byte[]> ticket_data = new ArrayList<byte[]>();
        ticket_data.add(pbk_bytes);
        ticket_data.add(addreBytes);
        ticket_data.add(portBytes);
        ticket_data.add(userBytes);
        ticket_data.add(timestamp);
        ticket_data.add(nonce);
        int length = pbk_bytes.length + addreBytes.length + addreBytes.length +
                     userBytes.length + timestamp.length + nonce.length + (ticket_data.size()*4);
        byte[] ticket = help.get_encrypted_concat_msg(length, ticket_data, aes);
        return ticket;
    }

   public boolean process_Login_Request(Fields login_1_fields) {
        System.out.println("Starting Login Session");
        try {
            //Fields login_1_fields = msgF.get_fields(login_1_string);
            System.out.println(login_1_fields.data.get("usernameEncrypted"));
            String username = getUsername(login_1_fields.data.get("usernameEncrypted"));
            System.out.println(login_1_fields.data.get("usernameEncrypted"));

            /**
             * Check to see if user already registered
             * If yes, exit the connection and thread
             */
            if(server.findUser(username))
            {
                System.out.println("User already logged in");
                clientSocket.close();
                return false;
            }
            else if(!this.server.handleUserData.findUser(username))
            {
                System.out.println("User not registered, Existing");
                clientSocket.close();
                return false;
            }

            serverDH = new CryptoDHProvider(false);
            System.out.println("Login Received from: " + username);

            //Calculate cookie and send cookie,n
            byte[] randNum = help.generateNonce();
            byte[] cookie = new Base64().encode(this.calculateCookie(clientSocket, randNum));
            System.out.println("cookie");

            //Get Salt
            byte[] salt = this.server.handleUserData.getSalt(username);
            //generate diffie hellman part signed with server's private key and send
            byte[] pbKDH = serverDH.getPublicKey();

            byte[] signature = new Base64().encode(server.serverRSA.signText(pbKDH));
            String login_2_string = msgF.set_login_2(cookie,salt,pbKDH,signature);

            System.out.println(login_2_string);
            //Send Login_2 message
            System.out.println("Sending login 2");
            outStream.println(login_2_string);
            System.out.println("sent login 2");

            String login_3_string = help.checkTimeout_getMessage(inStream);
            if(login_3_string == null)
            {
                System.out.println("Timeout on Socket, Existing thread");
                clientSocket.close();
                return false;
            }

            Fields login_3_field = msgF.get_fields(login_3_string);
            //Check if cookie received is correct
            byte[] receivedCookie = login_3_field.data.get("cookie");
            if(!Arrays.equals(cookie,receivedCookie)) {
                System.out.println("Cookie mismatch");
                clientSocket.close();
                //Thread.currentThread().interrupt();
                return false;
            }

            //Get next all data and decrypt it to get the diffie hellman key part
            System.out.println(login_3_field.data.get("Encrypted Client DH").length);
            byte[] client_dh = server.serverRSA.decryptText(login_3_field.data.get("Encrypted Client DH"));
            serverDH.setOtherPublicKey(client_dh);
            byte[] s1 = serverDH.getSecretKey();
            aes = new CryptoAESProvider(s1);
            //String credentials = new String(aes.decryptMessage(new Base64().decode(login_3_field.data.get("Encrypted Credentials"))));
            ArrayList<byte[]> login_3_data = help.get_decrypted_split_msg(login_3_field.data.get("Encrypted Credentials"),aes);

            if(login_3_data.size() != 4 || !Arrays.equals(login_3_data.get(0),username.getBytes())) {
                System.out.println("Wrong data for user: " + username);
                clientSocket.close();
                //Thread.currentThread().interrupt();
                return false;
            } else if (!this.server.handleUserData.validateUser(username, login_3_data.get(1))) {
                System.out.println("Wrong password for user: " + username);
                clientSocket.close();
                //Thread.currentThread().interrupt();
                return false;
            }
            byte[] nonce1 = login_3_data.get(3);
            byte[] pbK_user = login_3_data.get(2);

            publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pbK_user));

            ClientDetails clientDetails = new ClientDetails(username, clientSocket.getInetAddress(), clientSocket.getPort(), publicKey,aes);
            synchronized (this.server.ActiveUsers) {
                this.server.ActiveUsers.put(username, clientDetails);
            }

            this.user = username;
            /**
             * Send the last login Authentication message
             * It will have "nonce-1,timestamp"
             */
            java.util.Date date= new java.util.Date();
            Timestamp t = new Timestamp(date.getTime());
            byte[] timestamp = t.toString().getBytes();
            nonce1 = help.dec_Nonce(nonce1);
            ArrayList<byte[]> login_4_data = new ArrayList<byte[]>();
            login_4_data.add(timestamp);
            login_4_data.add(nonce1);
            int length = timestamp.length + nonce1.length + (login_4_data.size()*4);
            byte[] encryp_auth_msg = help.get_encrypted_concat_msg(length, login_4_data, aes);
            String auth_response = msgF.set_Auth_Response(encryp_auth_msg);
            outStream.println(auth_response);

        } catch (Exception e) {
            e.printStackTrace();
            try {
                if (clientSocket != null) {
                    clientSocket.close();
                }
            } catch (IOException e1) {
                //Nothing to do, Socket already closed
            }
            return false;
        }
       return true;
    }

    public void process_List_Request(Fields list_request)
    {
        if(list_request.data.size() != 1)
        {
            return;
        }

        try {
            byte[] nonce = aes.decryptMessage(list_request.data.get("nonce"));
            /* Retrieve the list of online users */
            byte[] user_list = server.get_active_users();
            byte[] response_nonce = help.dec_Nonce(nonce);
            ArrayList<byte[]> list_response = new ArrayList<byte[]>();
            list_response.add(user_list);
            list_response.add(response_nonce);
            int length = user_list.length + response_nonce.length + (list_response.size()*4);
            byte[] enc_list_response = help.get_encrypted_concat_msg(length,list_response,aes);
            String list_response_string = msgF.set_List_Response(enc_list_response);
            outStream.println(list_response_string);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean process_Chat_Request(Fields chat_request)
    {
        if(chat_request.data.size() != 1)
        {
            return false;
        }
        try {
            if(!chat_request.data.containsKey("Encrypted Talk Request"))
            {
                System.out.println("Encrypted Talk Request not present, Existing");
                return false;
            }
            ArrayList<byte[]> talk_request_list = help.get_decrypted_split_msg(chat_request.data.get("Encrypted Talk Request"),aes);
            if(talk_request_list.size()!=3)
            {
                System.out.println("Talk Request Information size not correct, Existing");
                return false;
            }
            String requested_username = new String(talk_request_list.get(0));
            byte[] nonce_ab = talk_request_list.get(1);
            byte[] nonce3 = talk_request_list.get(2);
            /* Retrieve the object of requested users */
            ClientDetails user_requested = (ClientDetails) server.ActiveUsers.get(requested_username);
            ClientDetails user_requesting = (ClientDetails) server.ActiveUsers.get(this.user);
            byte[] response_nonce = help.dec_Nonce(nonce3);
            java.util.Date date= new java.util.Date();
            Timestamp t = new Timestamp(date.getTime());
            byte[] timestamp_ab = t.toString().getBytes();
            //Get Ticket and hmac of ticket
            byte[] ticket = get_ticket(user_requesting.getPublicKey(),user_requesting.getInetAddress(),
                    user_requesting.getPort(), this.user,timestamp_ab,nonce_ab,user_requested.getAESProvider());
            byte[] hmac = server.serverRSA.signText(ticket);

            //get the Chat_grant message
            ArrayList<byte[]> chat_grant_list = new ArrayList<byte[]>();
            chat_grant_list.add(user_requested.getPublicKey().getEncoded());
            chat_grant_list.add(timestamp_ab);
            chat_grant_list.add(response_nonce);
            chat_grant_list.add(user_requested.getInetAddress().getAddress());
            chat_grant_list.add(ByteBuffer.allocate(4).putInt(user_requested.getPort()).array());
            int length = user_requested.getPublicKey().getEncoded().length + timestamp_ab.length +
                    response_nonce.length + user_requested.getInetAddress().getAddress().length + 4 + (chat_grant_list.size()*4);
            byte[] chat_grant = help.get_encrypted_concat_msg(length,chat_grant_list,aes);
            String talk_response_string = msgF.set_Talk_Response(ticket, hmac, chat_grant);
            this.outStream.println(talk_response_string);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            String failure_msg = msgF.set_Fail("Unable to generate ticket");
            this.outStream.println(failure_msg);
            return false;
        }
    }

    public void run()
    {
        String get_request;
        try {
            while((get_request = inStream.readLine()) != null)
            {
                Fields request_field = msgF.get_fields(get_request);
                String request = request_field.type;
                switch(request)
                {
                    case "LOGIN":
			/* Request From Client For Login */
                        if(!process_Login_Request(request_field)) {
                            if (this.user != null) {
                                synchronized (this.server.ActiveUsers) {
                                    this.server.ActiveUsers.remove(this.user);
                                }
                            }
                            return;
                        }
                        break;
                    case "LOGOUT":
			/* Request From Client For Logout */
                        //process_Logout_Request();
                        break;
                    case "LIST":
			/* Request From Client For List of Online Users */
                        process_List_Request(request_field);
                        break;
                    case "TALK":
			/* Request From Client For Chat with another online user */
                        process_Chat_Request(request_field);
                        break;
                    default:
                        // Rogue data. Packet will be dropped without any further consideration
                        break;
                }
            }
            System.out.println("User: " + this.user + " has exited");
            this.server.ActiveUsers.remove(this.user);
        } catch (IOException e) {
            System.out.println("User: " + this.user + " has exited");
            e.printStackTrace();
        }

    }
}
