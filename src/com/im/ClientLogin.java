package com.im;

import org.bouncycastle.util.encoders.Base64;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.Socket;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;

/**
 * Created by Yogesh on 4/1/2014.
 */
public class ClientLogin {
    Socket client_socket;
    MessageFormat msgF = new MessageFormat();
    HelperFunc help = new HelperFunc();
    Client client;

    public ClientLogin(Client client) {
        this.client = client;
    }

    protected Socket get_authenticated(InetAddress ip, int port,String username, String password, Client cli)
    {
        try{
            client_socket = new Socket(ip,port);
            BufferedReader inStream = new BufferedReader(new InputStreamReader(client_socket.getInputStream()));
            PrintWriter outStream = new PrintWriter(client_socket.getOutputStream(), true);
            byte[] encrypted_username = cli.client_RSA.encryptText(username.getBytes(),cli.client_RSA.getServerPublicKey());
            String login_1 = msgF.set_login_1(encrypted_username);

            outStream.println(login_1);

            /* Wait for server's response */
            String login_2_string = help.checkTimeout_getMessage(inStream);

            if(login_2_string == null) return null;


            Fields login_2_fields = msgF.get_fields(login_2_string);

            if(!login_2_fields.type.equals("login_2"))
            {
                System.out.println("Invalid Message");
                client_socket.close();
                return null;
            }


            if (!this.client.client_RSA.verifyText(login_2_fields.data.get("DH_Server"),
                    new Base64().decode(login_2_fields.data.get("Signature")), this.client.client_RSA.getServerPublicKey()))  {
                System.out.println("DH Public key verification failed");
                client_socket.close();
                return null;
            }

            cli.client_DH.setOtherPublicKey(login_2_fields.data.get("DH_Server"));

            byte[] s1 = cli.client_DH.getSecretKey();

            byte[] cookie = login_2_fields.data.get("cookie");
            byte[] salt = login_2_fields.data.get("salt");

            /* create shared AES key */
            cli.client_AES = new CryptoAESProvider(s1);

            /**
             * Login Arrow 3
             */
            byte[] pwd_hash = help.generate_pwdHash(password.getBytes(), salt);
            byte[] client_pbk = cli.client_RSA.getPublicKey().getEncoded();
            byte[] nonce1 = help.generateNonce();
            byte[] client_share = cli.client_DH.getPublicKey();

            byte[] encrypted_DH_client = cli.client_RSA.encryptText(client_share, cli.client_RSA.getServerPublicKey());
            ArrayList<byte[]> auth_details = new ArrayList<byte[]>();
            auth_details.add(username.getBytes());
            auth_details.add(pwd_hash);
            auth_details.add(client_pbk);
            auth_details.add(nonce1);
            int length = username.getBytes().length + pwd_hash.length + client_pbk.length + nonce1.length + (auth_details.size()*4);
            byte[] enc_auth_details = help.get_encrypted_concat_msg(length, auth_details, cli.client_AES);
            //If encryption fails, then we need to return null socket so Client can try again
            if(enc_auth_details == null)
            {
                return null;
            }

            String login_3_string = msgF.set_Auth_Request(enc_auth_details,cookie,encrypted_DH_client);

            outStream.println(login_3_string);

            /* Wait for server's response */
            String login_4_string = help.checkTimeout_getMessage(inStream);
            if(login_4_string == null)
                return null;

            //check the nonce received and timestamp
            Fields login_4_fields = msgF.get_fields(login_4_string);

           if(!login_4_fields.type.equals("set_Auth_Response") && !login_4_fields.data.containsKey("data"))
            {
                System.out.println("Does not contains key or invalid set_auth_message");
                client_socket.close();
                return null;
            }
            ArrayList<byte[]> login_4_data = help.get_decrypted_split_msg(login_4_fields.data.get("Encrypted Auth Response"), cli.client_AES);
            if(login_4_data.size() != 2)
            {
                System.out.println("Not enough arguments to compare");
                client_socket.close();
                return null;
            }
            if(!check_nonce(login_4_data.get(1),nonce1) ||!check_timestamp(login_4_data.get(0)))
            {
                System.out.println("Login 4 data Client Invalid data length");
                client_socket.close();
                return null;
            }

            return client_socket;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }

    protected boolean check_nonce(byte[] rec_nonce,byte[] nonce)
    {
        return Arrays.equals(nonce,help.inc_Nonce(rec_nonce));
    }

    protected boolean check_timestamp(byte[] rec_Timestamp)
    {
        try{
            Date date= new Date();
            Timestamp t = new Timestamp(date.getTime());
            SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd hh:mm:ss.SSS");
            Date parsedDate = dateFormat.parse(new String(rec_Timestamp));
            Timestamp timestamp1 = new Timestamp(parsedDate.getTime());

            long t_milli = t.getTime();
            long rec_milli = timestamp1.getTime();
            if(!((t_milli - 90000) < rec_milli) && !(rec_milli < (t_milli + 90000)))
                return false;

            return true;

        }
        catch(Exception e){
            System.out.println("Invalid Timestamp");
            return false;
        }
    }
}
