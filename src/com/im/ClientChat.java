package com.im;

import com.google.gson.Gson;
import org.json.simple.JSONObject;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.util.*;

/**
 * Created by adityarao on 4/6/14.
 */
public class ClientChat extends Thread {

    public ClientChat (Client client, int port) {
        this.client = client;
        System.out.println("Listening for client CHAT requests on port: " + port);

        try {
            this.socket = new DatagramSocket(port);

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        byte[] buffer = new byte[10000];
        try {
            while (this.socket != null) {
                DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                this.socket.receive(packet);
                checkPacket(new String(buffer, 0, packet.getLength(), "UTF-8"), packet.getAddress(), packet.getPort());
                //System.out.println("From " + packet.getAddress().getHostAddress() + " Msg: " + new String(buffer));
            }
        } catch (SocketException e) {
            System.out.println("Client not listening anymore.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void checkPacket(String buffer, InetAddress address, int port) {
        HelperFunc help = new HelperFunc();
        try {
            Fields msgField = new MessageFormat().get_fields(buffer);
            if (msgField != null) {
                if (msgField.type.equals("Talk_Request")) {
                    byte[] encryptedTicket = msgField.data.get("Ticket");
                    byte[] encryptedKey = msgField.data.get("Session");
                    byte[] iv = msgField.data.get("IV");
                    byte[] signature = msgField.data.get("Signature");
                    ArrayList<byte[]> ticket =
                            new HelperFunc().get_decrypted_split_msg(msgField.data.get("Ticket"), this.client.client_AES);

                    /* Check for IP, Port and others. */
                    synchronized (this.usersConnected) {
                        if (usedTickets.contains(encryptedTicket) ||
                                usersConnected.containsKey(new String(ticket.get(3))) ||
                                !Arrays.equals(address.getAddress(), ticket.get(1)) ||
                                ByteBuffer.wrap(ticket.get(2)).getInt() != port)
                            return;
                    }
                    /* Adds the ticket to used list */
                    usedTickets.add(encryptedTicket);

                    PublicKey otherPubKey = CryptoRSAProvider.getPublicKey(ticket.get(0));

                    if (!CryptoRSAProvider.verifyText(ticket.get(5), signature, otherPubKey)) {
                        return;
                    }

                    /* Verfication done, now add the user to list and send challenge response */
                    String username = new String(ticket.get(3));
                    ClientTalkDetails clientTalkDetails = new ClientTalkDetails(username, encryptedTicket, address, port,
                                                                otherPubKey, ticket.get(4), ticket.get(5), null);

                    /* Extract the session key Kab */
                    byte[] sessionKey = this.client.client_RSA.decryptText(encryptedKey);
                    CryptoAESProvider aesProvider = new CryptoAESProvider(sessionKey, iv);
                    clientTalkDetails.setAesProvider(aesProvider);

                    /* Generate response to the Talk Request */

                    /* Encrypt Timestamp */
                    byte[] msgToSend = ticket.get(4);
                    //byte[] msgToSend = aesProvider.encryptMessage(ticket.get(4));

                    /* Generate nonce for freshness */
                    byte[] nonce = clientTalkDetails.generateNonce();
                    ArrayList<byte[]> chat_response = new ArrayList<byte[]>();
                    chat_response.add(msgToSend);
                    chat_response.add(nonce);
                    int length = msgToSend.length + nonce.length + (chat_response.size()*4);
                    byte[] encrypted_response = help.get_encrypted_concat_msg(length, chat_response,clientTalkDetails.getAesProvider());
                    byte[] msg = new MessageFormat().set_Initiate_Chat_Response(encrypted_response)
                                 .getBytes("UTF-8");

                    /* Send UDP Packet */
                    DatagramPacket packet = new DatagramPacket(msg, msg.length,
                            clientTalkDetails.getInetAddress(), clientTalkDetails.getPort());
                    clientTalkDetails.setLoggingIn(true);
                    this.socket.send(packet);

                    /* Add the clientTalkDetails to the usersConnected list */
                    clientTalkDetails.setTime();
                    synchronized (this.usersConnected) {
                        usersConnected.put(clientTalkDetails.getUser(), clientTalkDetails);
                    }
                }
                else if (msgField.type.equals("Talk_Response")) {
                    //System.out.println("\t\tTalk Response");
                    byte[] encryptedResponse = msgField.data.get("Encrypted Response");
                    //byte[] encryptedChallenge = msgField.data.get("Response Challenge");
                    ClientTalkDetails client = getClientByIP(address, port);
                    if (client != null &&
                        Arrays.equals(client.getInetAddress().getAddress(), address.getAddress()) &&
                        client.getPort() == port) {
                        if (client.isLoggingIn() && !client.isLoggedOut()) {
                            /* Check if the other client is able to extract the timestamp */
                            ArrayList<byte[]> decryptedResponse = help.get_decrypted_split_msg(encryptedResponse,client.getAesProvider());
                            if (Arrays.equals(client.getTimestamp(),
                                              decryptedResponse.get(0))) {
                                /* Client connection established. Now let the other client know that connection is established */
                                client.setLoggingIn(false);

                                /* Decrement the nonce sent by other client */
                                byte[] nonce1 = decryptedResponse.get(1);
                                if (!client.appendNonce(nonce1)) {
                                    client.setLoggedOut(true);
                                    return;
                                }
                                byte[] decNonce = HelperFunc.dec_Nonce(nonce1);

                                /* Generate new fresh nonce */
                                byte[] nonce2 = client.generateNonce();
                                if (nonce2 == null) {
                                    System.out.println("Unable to generate nonce");
                                    client.setLoggedOut(true);
                                }
                                //System.out.println(new BigInteger(HelperFunc.dec_Nonce(nonce1)));
                                ArrayList<byte[]> success = new ArrayList<byte[]>();
                                success.add(decNonce);
                                success.add(nonce2);
                                int length = decNonce.length + nonce2.length + (success.size()*4);
                                byte[] encrypted_success = help.get_encrypted_concat_msg(length ,success, client.getAesProvider());
                                // Change
                                /* Send the Success message */
                                byte[] msg = new MessageFormat().set_Connection_Success(encrypted_success)
                                                                .getBytes("UTF-8");

                                DatagramPacket packet = new DatagramPacket(msg, msg.length,
                                        client.getInetAddress(), client.getPort());

                                this.socket.send(packet);
                                sendMessage(client.getUser(), client.initialMessage);
                                client.setTime();
                            }
                        }
                    }
                } else if (msgField.type.equals("Talk_Success")) {
                    /* This is to check if the connection is established on the requesting client */
                    byte[] encryptedChallenge = msgField.data.get("Encrypted_nonces");
                    ArrayList<byte[]> decryptedChallenge;
                    ClientTalkDetails client = getClientByIP(address, port);
                    //System.out.println(new BigInteger(HelperFunc.inc_Nonce(client.getAesProvider().decryptMessage(encryptedChallenge))));
                    if (client != null &&
                        Arrays.equals(client.getInetAddress().getAddress(), address.getAddress()) &&
                        client.getPort() == port) {
                        if (client.isLoggingIn() && !client.isLoggedOut()) {
                            /* Check if the nonce is one less than the last nonce generated */
                            decryptedChallenge = help.get_decrypted_split_msg(encryptedChallenge,client.getAesProvider());
                            if (client.checkNonce(decryptedChallenge.get(0))) {
                                /* Store the other one for future */
                                client.appendNonce(decryptedChallenge.get(1));
                                client.setLoggingIn(false);
                                //System.out.println("Hurray");
                                client.setTime();
                            } else
                                System.out.println("Not done!");
                        }
                    }
                } else if (msgField.type.equals("Message")) {
                    ClientTalkDetails client = getClientByIP(address, port);
                    //System.out.println(new BigInteger(HelperFunc.inc_Nonce(client.getAesProvider().decryptMessage(encryptedChallenge))));
                    if (client != null &&
                        Arrays.equals(client.getInetAddress().getAddress(), address.getAddress()) &&
                        client.getPort() == port &&
                        !client.isLoggingIn() && !client.isLoggedOut()) {
                        ArrayList<byte[]> decryptedChat = help.get_decrypted_split_msg(msgField.data.get("Chat_and_nonce"),client.getAesProvider());
                        byte[] decryptedChallenge = decryptedChat.get(1);
                        //System.out.println(client.getUser() + ": " +
                            //    new String (decryptedChat.get(0)));
                        /* Check if the nonce is one less than the last nonce generated */
                        if (client.checkNonce(decryptedChallenge)) {
                            /* Store the other one for future */
                            client.appendNonce(decryptedChat.get(2));
                            System.out.println(client.getUser() + ": " +
                                                new String (decryptedChat.get(0)));
                            client.setLoggingIn(false);
                            client.setTime();
                        } else
                            System.out.println("Message: Not done!");
                    }
                } else if (msgField.type.equals("Disconnect")) {
                    ClientTalkDetails client = getClientByIP(address, port);
                    //System.out.println(new BigInteger(HelperFunc.inc_Nonce(client.getAesProvider().decryptMessage(encryptedChallenge))));
                    if (client != null &&
                        Arrays.equals(client.getInetAddress().getAddress(), address.getAddress()) &&
                        client.getPort() == port &&
                        !client.isLoggingIn() && !client.isLoggedOut() && !client.getDisconnect()) {
                        byte[] encryptedChallenge = msgField.data.get("Old");
                        /* Check if the nonce is one less than the last nonce generated */
                        if (client.checkNonce(client.getAesProvider().decryptMessage(encryptedChallenge))) {
                            /* Store the other one for future */
                            client.appendNonce(client.getAesProvider().decryptMessage(msgField.data.get("Fresh")));
                            this.client.user_info.remove(client.getUser());

                            /* Decrement the nonce sent by other client */
                            byte[] nonce1 = client.getAesProvider().decryptMessage(msgField.data.get("Fresh"));
                            if (!client.appendNonce(nonce1)) {
                                client.setLoggedOut(true);
                                return;
                            }
                            byte[] decNonce = client.getAesProvider().encryptMessage(HelperFunc.dec_Nonce(nonce1));

                                /* Generate new fresh nonce */
                            byte[] nonce2 = client.generateNonce();
                            if (nonce2 == null) {
                                System.out.println("Unable to generate nonce");
                                client.setLoggedOut(true);
                            }
                            //System.out.println(new BigInteger(HelperFunc.dec_Nonce(nonce1)));

                            HashMap<String, byte[]> data = new HashMap<>();
                            data.put("Fresh", nonce2);
                            data.put("Old", decNonce);
                            JSONObject jsonObject = new JSONObject();
                            jsonObject.put("type", "Disconnect_Success");
                            jsonObject.put("data", data);
                            Gson gson = new Gson();
                            byte[] msg = gson.toJson(jsonObject).getBytes("UTF-8");

                            DatagramPacket packet = new DatagramPacket(msg, msg.length,
                                    client.getInetAddress(), client.getPort());

                            this.socket.send(packet);
                            sendMessage(client.getUser(), client.initialMessage);
                            synchronized (this.usersConnected) {
                                usersConnected.remove(client.getUser());
                            }
                            System.out.println(client.getUser() + " Disconnected");
                        } else
                            System.out.println("Not disconnecting!");
                    }
                }else if (msgField.type.equals("Disconnect_Success")) {
                    ClientTalkDetails client = getClientByIP(address, port);

                    if (client != null &&
                        Arrays.equals(client.getInetAddress().getAddress(), address.getAddress()) &&
                        client.getPort() == port &&
                        !client.isLoggingIn() && !client.isLoggedOut() && client.getDisconnect()) {
                        byte[] encryptedChallenge = msgField.data.get("Old");
                        /* Check if the nonce is one less than the last nonce generated */
                        if (client.checkNonce(client.getAesProvider().decryptMessage(encryptedChallenge))) {
                            /* Store the other one for future */
                            client.appendNonce(client.getAesProvider().decryptMessage(msgField.data.get("Fresh")));
                            this.client.user_info.remove(client.getUser());
                            synchronized (this.usersConnected) {
                                usersConnected.remove(client.getUser());
                            }
                            System.out.println(client.getUser() + " Disconnected");
                        } else
                            System.out.println("Not disconnecting!");
                    }
                }
            }
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean initiateChatRequest (ClientTalkDetails clientTalkDetails, String message) {

        byte[] chatRequest = new byte[1024];
        chatRequest = "Hello Word".getBytes();

        try {
            byte[] aesProvider = clientTalkDetails.generateSecretKey();
            byte[] encryptedKey = CryptoRSAProvider.encryptText(aesProvider, clientTalkDetails.getPublicKey());
            byte[] signedNonce = clientTalkDetails.getSignedNonce();

            // Change
            MessageFormat messageFormat = new MessageFormat();
            byte[] msg = messageFormat.
                            set_Initiate_Chat_Request(clientTalkDetails.getTicket(), encryptedKey,
                                    clientTalkDetails.getIV(), signedNonce);

            new MessageFormat().get_fields(new String(msg));

            DatagramPacket packet = new DatagramPacket(msg, msg.length,
                    clientTalkDetails.getInetAddress(), clientTalkDetails.getPort());
            clientTalkDetails.setLoggingIn(true);
            this.socket.send(packet);
            clientTalkDetails.initialMessage = message;
            synchronized (this.usersConnected) {
                usersConnected.put(clientTalkDetails.getUser(), clientTalkDetails);
            }
            clientTalkDetails.setTime();
            return true;
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    /* Kills the thread by closing the datagram socket */
    public void kill() {
        this.socket.close();
    }

    /* Checks if the user is already connected. Also check if the user has already logged out. */
    public boolean userConnected (String username) {
        synchronized (this.usersConnected) {
            return this.usersConnected.containsKey(username) && !this.usersConnected.get(username).isLoggedOut();
        }
    }

    public ClientTalkDetails getClientByIP (InetAddress inetAddress, int port) {
        synchronized (this.usersConnected) {
            Iterator<Map.Entry<String, ClientTalkDetails>> it = usersConnected.entrySet().iterator();
            while (it.hasNext()) {
                ClientTalkDetails clientTalkDetails = it.next().getValue();
                if (clientTalkDetails.getInetAddress().equals(inetAddress) && clientTalkDetails.getPort() == port) {
                    return clientTalkDetails;
                }
            }
        }
        return null;
    }
    public void sendDisconnect(String username)
    {
        ClientTalkDetails clientTalkDetails;
        try {
            synchronized (this.usersConnected) {
                clientTalkDetails  = usersConnected.get(username);
            }
            if (clientTalkDetails != null && !clientTalkDetails.isLoggingIn() && !clientTalkDetails.isLoggedOut()) {
                /* Send the message */
                HashMap<String, byte[]> data = new HashMap<>();
                data.put("Fresh", clientTalkDetails.generateNonce());
                data.put("Old", clientTalkDetails.getLastNonceDec());
                JSONObject jsonObject = new JSONObject();
                jsonObject.put("type", "Disconnect");
                jsonObject.put("data", data);
                Gson gson = new Gson();
                byte[] msg = gson.toJson(jsonObject).getBytes("UTF-8");
                clientTalkDetails.setDisconnect(true);
                DatagramPacket packet = new DatagramPacket(msg, msg.length,
                        clientTalkDetails.getInetAddress(), clientTalkDetails.getPort());

                this.socket.send(packet);
                clientTalkDetails.setTime();
            } else {
                System.out.println("User not online");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public void sendMessage(String username, String message) {
        try {
            HelperFunc help = new HelperFunc();
            ClientTalkDetails clientTalkDetails;
            synchronized (this.usersConnected) {
                clientTalkDetails = usersConnected.get(username);
            }
            if (clientTalkDetails != null && !clientTalkDetails.isLoggingIn() && !clientTalkDetails.isLoggedOut()) {
                // Changed
                /* Send the message */
                ArrayList<byte[]> msgToSend = new ArrayList<byte[]>();
                byte[] last_nonce = clientTalkDetails.getLastNonceDec();
                byte[] new_nonce= clientTalkDetails.generateNonce();
                msgToSend.add(message.getBytes());
                msgToSend.add(last_nonce);
                msgToSend.add(new_nonce);
                int length = message.getBytes().length +last_nonce.length + new_nonce.length + (msgToSend.size()*4);
                byte[] msg_encrypt = help.get_encrypted_concat_msg(length,msgToSend,clientTalkDetails.getAesProvider());
                byte[] msg = new MessageFormat()
                            .set_Chat_Message(msg_encrypt)
                            .getBytes("UTF-8");

                DatagramPacket packet = new DatagramPacket(msg, msg.length,
                        clientTalkDetails.getInetAddress(), clientTalkDetails.getPort());

                this.socket.send(packet);
                clientTalkDetails.setTime();
            } else {
                System.out.println("User not online");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private Client client;
    private DatagramSocket socket;
    protected HashMap<String, ClientTalkDetails> usersConnected = new HashMap<String, ClientTalkDetails>();
    private ArrayList<byte[]> usedTickets = new ArrayList<>();
}
