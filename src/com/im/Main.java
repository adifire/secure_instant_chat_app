package com.im;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;

public class Main {

    public static void main(String[] args) throws Exception {
        BigInteger p = new BigInteger("71");
        String msg = "Hello World";

        /*
        Random rnd = new Random();
        HashMap<String, String> users = new HashMap<String, String>();
        users.put("Adi", "ida");
        users.put("Yogi", "igoY");
        users.put("Neu", "euN");

        HandleUserData.generateUserData("user.dat", users);
        */

        HandleUserData h = new HandleUserData("user.dat");
        h.showUsers();
        //System.out.println(HandleUserData.findUser("Adi"));

        //System.out.println(HandleUserData.validateUser("Adi",
        //        HelperFunc.generate_pwdHash("asa".getBytes(), HandleUserData.getSalt("Adi"))));

        byte[] a = new Base64().encode(new Base64().encode("Helloas faksfjas fans fas dka ".getBytes()));
        SecureRandom rnd = new SecureRandom();
        p = BigInteger.probablePrime(1024, rnd);
        System.out.println(BigInteger.valueOf(2));
        CryptoDHProvider dh1 = new CryptoDHProvider(false);
        CryptoDHProvider dh2 = new CryptoDHProvider(false);
        dh1.setOtherPublicKey(dh2.getPublicKey());
        dh2.setOtherPublicKey(dh1.getPublicKey());
        byte[] s1 = dh1.getSecretKey();
        byte[] s2 = dh2.getSecretKey();
        System.out.println(dh1.getPublicKey().length);
        System.out.println(Arrays.equals(s1,s2));
        System.out.println(s1.length);
        System.out.println(s1);
        CryptoAESProvider aes = new CryptoAESProvider(s1);
        CryptoAESProvider aes2 = new CryptoAESProvider(s2);
        byte[] e = aes.encryptMessage(msg.getBytes());
        System.out.println(dh1.getPublicKey().length);
        System.out.println(new String(aes2.decryptMessage(new Base64().decode(e))));

        //converting ip to bytes and back
        InetAddress address =
                InetAddress.getByName("192.168.1.1");
        byte[] bytes = address.getAddress();
        for (byte b : bytes)
        {
            System.out.println(b & 0xFF);
        }

        InetAddress d = InetAddress.getByAddress(bytes);
        System.out.println(d.equals(address));



        //System.out.println(new String (rsa.decryptText(rsa.encryptText(msg.getBytes(), rsa.getPublicKey()))));

        /*
        CryptoAESProvider aes3 = new CryptoAESProvider();
        CryptoAESProvider aes4 = new CryptoAESProvider(aes3.getSecretKey(), aes3.getIV());

        //System.out.println(aes4.decryptMessage(aes3.encryptMessage(msg.getBytes("UTF-8"))));

        CryptoDHProvider dh = new CryptoDHProvider(false);
        MessageFormat mf = new MessageFormat();
        //String json = mf.set_login_1(rsa.encryptText(dh2.getPublicKey(), rsa.getPublicKey()));
        //Fields fields = mf.get_fields(json);
        //System.out.print(rsa.decryptText(fields.data.get("usernameEncrypted")));
        */
    }
}
