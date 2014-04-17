package com.im;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/**
 * Created by Yogesh on 3/31/2014.
 */
public class Client {

    public Client()
    {
        try {
            this.client_RSA = new CryptoRSAProvider(2048);
            this.client_DH = new CryptoDHProvider(false);
            client_RSA.setServerPublicKey("receiver_public_key.der");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    Socket get_info_authenticate(InetAddress server_ip,int server_port, Client cl) throws InterruptedException {
        System.out.println("Starting Login");
        Thread.sleep(200);
        Socket client_local;
        String username;
        try {
            BufferedReader console_read = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Welcome to the Chat");
            System.out.println("Enter Your Information to Login");
            System.out.print("Enter Your Username: ");
            username = console_read.readLine();
            while (username.equals("") || username.equals(" ") || username == null) {
                System.out.print("Username Cannot be blank\nEnter Your Username: ");
                username = console_read.readLine();
            }
            System.out.print("Enter Your Password: ");
            String password = console_read.readLine();
            ClientLogin c_l = new ClientLogin(this);
            cl.username=username;
            return c_l.get_authenticated(server_ip, server_port, username, password,cl);
        }
        catch (Exception e)
        {
            return null;
        }
    }

    public boolean getList () {
        HelperFunc help = new HelperFunc();
        try {
            byte[] nonce1 = help.generateNonce();
            //this.client_RSA.encryptText(nonce1, this.client_RSA.getS);
            String list_request = new MessageFormat().set_List_Request(this.client_AES.encryptMessage(nonce1));
            (new PrintWriter(this.client_socket.getOutputStream(), true)).println(list_request);
            String list_response = help.checkTimeout_getMessage(new BufferedReader(new InputStreamReader(this.client_socket.getInputStream())));
            if(list_response == null)
            {
                System.out.println("No LIST response from Server, Exiting");
                return false;
            }
            Fields list_response_fields = new MessageFormat().get_fields(list_response);

            if (!list_response_fields.type.equals("List_Response")) {
                System.out.println("No LIST response from Server, Exiting");
                return false;
            }
            ArrayList<byte[]> data = help.get_decrypted_split_msg(list_response_fields.data.get("Encrypted List"), this.client_AES);
            if (data.size() != 2) {
                System.out.println("Not proper response for LIST from Server, Exiting");
                return false;
            }
            if (!Arrays.equals(nonce1, help.inc_Nonce(data.get(1)))) {
                System.out.println("Wrong nonce from Server, Exiting");
                return false;
            }

            ByteArrayInputStream bais = new ByteArrayInputStream(data.get(0));
            DataInputStream in = new DataInputStream(bais);
            if (in.available() > 0) {
                System.out.println ("List of Online Users");
            }
            while (in.available() > 0) {
                String element = in.readUTF();
                System.out.println("\t" + element);
            }
            //System.out.println("\n");
        } catch (Exception e) {
            e.printStackTrace();

        }
        return false;
    }

    //Get Ticket from the server for a User to Talk to
    public boolean getTicket(String username, String message)
    {
        HelperFunc help = new HelperFunc();
        try {
            byte[] nonce_ab = help.generateNonce();
            byte[] nonce3 = help.generateNonce();
            ArrayList<byte[]> talk_request_list = new ArrayList<byte[]>();
            talk_request_list.add(username.getBytes());
            talk_request_list.add(nonce_ab);
            talk_request_list.add(nonce3);
            int length = username.getBytes().length + nonce3.length + nonce_ab.length + (talk_request_list.size()*4);
            byte[] encryptedTalk_request = help.get_encrypted_concat_msg(length, talk_request_list, this.client_AES);

            String talk_request = new MessageFormat().set_Talk_Request(encryptedTalk_request);
            (new PrintWriter(this.client_socket.getOutputStream(), true)).println(talk_request);

            String talk_response = help.checkTimeout_getMessage(new BufferedReader(new InputStreamReader(this.client_socket.getInputStream())));
            if(talk_response == null)
            {
                System.out.println("No TALK response from Server, Exiting");
                return false;
            }
            Fields talk_response_fields = new MessageFormat().get_fields(talk_response);

            if (!talk_response_fields.type.equals("Talk_Response")) {
                if (talk_response_fields.type.equals("Error"))
                    System.out.println(talk_response_fields.status);
                else
                    System.out.println("No Talk response from Server, Exiting");
                return false;
            }

            if (talk_response_fields.data.size() != 3) {
                System.out.println("Not proper response for TALK from Server, Exiting");
                return false;
            }
            byte[] encrypted_talk_response = talk_response_fields.data.get("Chat_Grant");
            ArrayList<byte[]> chat_grant = help.get_decrypted_split_msg(encrypted_talk_response, this.client_AES);
            if (chat_grant.size()!= 5) {
                System.out.println("Wrong Chat Grant, Exiting");
                return false;
            }
            if (!Arrays.equals(nonce3, help.inc_Nonce(chat_grant.get(2)))) {
                System.out.println("Wrong nonce from Server, Exiting");
                return false;
            }

            byte[] tgt = talk_response_fields.data.get("TGT");
            byte[] hmac = talk_response_fields.data.get("HMAC");
            if(!client_RSA.verifyText (tgt, hmac, client_RSA.getServerPublicKey()))
            {
                System.out.println("HMAC Verification Failed, Exiting");
                return false;
            }
            ClientTalkDetails clientTalkDetails =
                    new ClientTalkDetails(username, tgt, InetAddress.getByAddress(chat_grant.get(3)),
                                        ByteBuffer.wrap(chat_grant.get(4)).getInt(),
                                        KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(chat_grant.get(0))),
                                        chat_grant.get(1), nonce_ab, this.client_RSA.signText(nonce_ab));
            user_info.put(username,clientTalkDetails);
            return this.clientChat.initiateChatRequest(clientTalkDetails, message);
        }
        catch (Exception e)
        {
            return false;
        }
    }


    public void handleUserInput () {
        BufferedReader fromConsole = new BufferedReader(new InputStreamReader(System.in));
        String userInput;
        System.out.println(this.client_socket.getInetAddress().getHostAddress());
        System.out.print("\n===================================\n" +
                "\nType LIST to get list of online users \n" +
                "Type SEND <username> to chat to a client \n" );
        try {
            while (true) {

                if ((userInput = fromConsole.readLine()) != null) {
                    if (userInput.toLowerCase().startsWith("list")) {
                        getList();
                    } else if (userInput.toLowerCase().startsWith("send")) {
                        String[] split = userInput.split(" ");
                        if (split.length < 3) {
                            System.out.println("Invalid Request");
                            continue;
                        }
                        String username = split[1];
                        if (username.equals(this.username)) {
                            System.out.println("Invalid Request");
                            continue;
                        }
                        String message = userInput.substring(userInput.indexOf(username) + username.length() + 1);
                        if (!this.clientChat.userConnected(username))
                            getTicket(username, message);
                        else {
                            this.clientChat.sendMessage(username, message);
                        }
                    } else if (userInput.toLowerCase().startsWith("close") || userInput.toLowerCase().startsWith("exit")) {
                        break;
                    } else if(userInput.toLowerCase().startsWith("disconnect")){
                        String[] split = userInput.split(" ");
                        if (split.length < 2) {
                            System.out.println("Invalid Request: Provide username");
                            continue;
                        }
                        String username = split[1];
                        if (username.equals(this.username)) {
                            System.out.println("Invalid Request: Cannot disconnect yourself!");
                            continue;
                        }

                        if (!this.clientChat.userConnected(username))
                            this.clientChat.sendDisconnect(username);
                    }
                    else {
                        System.out.println("Invalid Request.");
                    }
                }
                else
                    break;
            }
            this.client_socket.close();
            this.clientChat.kill();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args)
    {

        Client cl = new Client();

        try {
            //InetAddress server_ip = InetAddress.getByName(args[0]);
            InetAddress server_ip = InetAddress.getByName("127.0.0.1");
            int server_port= Integer.parseInt(args[0]);

            while ((cl.client_socket = cl.get_info_authenticate(server_ip, server_port, cl)) == null) {
                System.out.println("Wrong username or password. Try again\n");
            }

            System.out.println("Successfully Authenticated");

            /* Spawn new thread to listen to client CHAT requests */
            cl.clientChat = new ClientChat(cl, cl.client_socket.getLocalPort());
            cl.clientChat.start();
            Thread non_active_clients = new CheckClient(cl.clientChat);
            non_active_clients.start();

            /* Handle user input */
            cl.handleUserInput();
            non_active_clients.interrupt();
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }

    String username;
    CryptoRSAProvider client_RSA;
    CryptoDHProvider client_DH;
    CryptoAESProvider client_AES;
    PublicKey pbk_server;
    private static Socket client_socket;
    HashMap<String,Object> user_info = new HashMap<>();
    ClientChat clientChat;
}
