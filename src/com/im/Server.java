package com.im;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Iterator;

/**
 * Created by Yogesh on 3/28/2014.
 */
public class Server {

    private ServerSocket serverSocket;
    //private InetAddress ip_address;
    private int port;
    HashMap<String, Object> ActiveUsers = new HashMap<String, Object>();
    CryptoRSAProvider serverRSA;
    HandleUserData handleUserData;

    //public Server(InetAddress ip,int port)
    public Server(int port)
    {
        //this.ip_address = ip;
        try {
            this.serverRSA = new CryptoRSAProvider("receiver_public_key.der", "receiver_key.der");
            this.port = port;
            this.handleUserData = new HandleUserData("user.dat");
        } catch (Exception e) {
            System.out.println("Error in creating Crypto class");
            e.printStackTrace();
        }

    }

    public void startServer()
    {
        System.out.println("Server Initialized");

        try
        {
            //serverSocket = new ServerSocket();
            serverSocket = new ServerSocket(port);
            //serverSocket.setReuseAddress(true);
        }
        catch(Exception e)
        {
            e.printStackTrace();
            System.out.println("Server socket initialization error");
            return;
        }

        while(true)
        {
            try
            {
                Socket clientSocket = serverSocket.accept();
                new Thread(new Handle_client_request(clientSocket,this)).start();
            } catch (IOException e) {
                e.printStackTrace();
                break;
            }
        }
    }

    protected byte[] getUserHash(String username)
    {
        HelperFunc h = new HelperFunc();
        return h.generate_pwdHash("b".getBytes(),"c".getBytes());
    }

    public boolean findUser (String username) {
        synchronized (this.ActiveUsers) {
            if (!this.ActiveUsers.containsKey(username))
                return false;
            return true;
        }
    }

    public byte[] decryptData (byte[] encryptedData) {
        try {
            return this.serverRSA.decryptText(encryptedData);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public byte[] get_active_users()
    {
        synchronized (this.ActiveUsers) {
            Iterator it = this.ActiveUsers.keySet().iterator();
            // get theuser list from Hashmap of active_users
            // write to byte array
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream out = new DataOutputStream(baos);
            while (it.hasNext()) {
                try {
                    out.writeUTF((String) it.next());
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            byte[] bytes = baos.toByteArray();
            return bytes;
        }

        /*// read from byte array
        ByteArrayInputStream bais = new ByteArrayInputStream(bytes);
        DataInputStream in = new DataInputStream(bais);
        while (in.available() > 0) {
            String element = in.readUTF();
            System.out.println(element);
        }*/
    }

    public static void main(String[] args)
    {
        /* Check for ip and port here */
        try {
            int port = Integer.parseInt(args[0]);
            Server s = new Server(port);
            s.startServer();
        } catch (Exception e) {
            System.out.println("Wrong input. Usage: java -cp .:../lib/* com.im.Server <port>");
        }
    }
}
