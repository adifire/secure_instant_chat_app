package com.im;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Socket;
import java.security.MessageDigest;

/**
 * Created by adityarao on 4/4/14.
 */
public class ClientService extends Thread {

    public ClientService (Server server, Socket socket) throws Exception {
        this.server = server;
        this.clientSocket = socket;
        this.fromClient = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));
        this.toClient = new DataOutputStream(this.clientSocket.getOutputStream());
        this.clientSocket.setSoTimeout(6000);
    }

    @Override
    public void run() {
        /*
            Authenticate Client
            Service LIST request
            Grant client CHAT request
         */

        authenticateUser ();

    }

    private boolean authenticateUser() {
        if (this.clientSocket == null)
            return false;

        try {
            /*
               Validate the client's first message and then proceed with generation of DH public key.
             */
            String first_leg = fromClient.readLine();
            Fields fields = new MessageFormat().get_fields(first_leg);
            if (fields == null)
                return false;

            /* Check if username exists and has not already logged in */
            String username = this.getUsername(fields.data.get("username"));
            if (username == null || this.server.findUser(username))
                return false;

            /* Now generate a new DH public key and cookie for the client */
            CryptoDHProvider dhProvider = new CryptoDHProvider(false);
            byte[] dhYParm = dhProvider.getPublicKey();
            this.sessionCookie = generateCookie();

            //byte[] salt =

        } catch (IOException e) {
            e.printStackTrace();
            return false;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return false;
    }

    private String getUsername (byte[] usernameEncrypted) {
        return new String(this.server.decryptData(usernameEncrypted));
    }

    protected byte[] generateCookie() {
        try {
            /* Get the ip address of the user */
            byte[] ip = this.clientSocket.getInetAddress().getAddress();
            //byte[] nBytes = String.valueOf(n).getBytes();
            byte[] cat = HelperFunc.concatenateArrays(ip, HelperFunc.generateNonce());

            //Calculate the hash (cookie)
            byte[] ret = MessageDigest.getInstance("SHA-256").digest(cat);

            return ret;
        }
        catch(Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    Server server;
    Socket clientSocket;
    BufferedReader fromClient;
    DataOutputStream toClient;
    byte[] sessionCookie;
}
