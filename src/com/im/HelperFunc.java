package com.im;

import java.io.BufferedReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Created by Yogesh on 3/28/2014.
 */
public class HelperFunc {

    public static byte[] concatenateArrays(byte[] A, byte[] B) {
        int aLen = A.length;
        int bLen = B.length;
        byte[] C = new byte[aLen + bLen];
        System.arraycopy(A, 0, C, 0, aLen);
        System.arraycopy(B, 0, C, aLen, bLen);
        return C;
    }

    //Nonce generation
    public static byte[] generateNonce() {

        SecureRandom secureRandom = new SecureRandom();
        byte[] b = new byte[8];
        secureRandom.nextBytes(b);
        return b;
    }

    public static byte[] generateSalt () {
        SecureRandom secureRandom = new SecureRandom();
        byte[] b = new byte[8];
        secureRandom.nextBytes(b);
        return b;
    }

    public static byte[] generate_pwdHash(byte[] pwd,byte[] salt)
    {

        final byte[] salted = new byte[pwd.length + salt.length];
        try {
            final MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
            System.arraycopy(pwd, 0, salted, 0, pwd.length);
            System.arraycopy(salt, 0, salted, pwd.length, salt.length);
            Arrays.fill(pwd, (byte) 0x00);

            /* compute SHA-256 digest */
            shaDigest.reset();
            pwd = shaDigest.digest(salted);
            Arrays.fill(salted, (byte) 0x00);
        }
        catch (Exception e)
        {
            System.out.println("Hashing failed");
            return null;
        }

        return pwd;
    }

    // Decrement Nonce

    protected static byte[] dec_Nonce(byte[] nonce)
    {
        BigInteger n = new BigInteger(nonce);
        BigInteger dec=new BigInteger("-1");
        return n.add(dec).toByteArray();

    }

    // Increment Nonce
    protected static byte[] inc_Nonce(byte[] nonce)
    {
        BigInteger n = new BigInteger(nonce);
        BigInteger dec=new BigInteger("1");
        return n.add(dec).toByteArray();

    }

    // Generate Hash of Pssword

    protected static byte[] get_concat_msg(int length,ArrayList<byte[]> data)
    {
        byte[] encrypt = new byte[length];
        int l = 0;

        for(int i=0; i<data.size(); i++)
        {
            byte[] d = ByteBuffer.allocate(4).putInt(data.get(i).length).array();
            byte[] gen = concatenateArrays(d,data.get(i));
            System.arraycopy(gen, 0, encrypt, l, gen.length);
            l = l + data.get(i).length + d.length;

        }

        return encrypt;
    }

    protected static ArrayList<byte[]> get_split_msg(byte[] encryp_data)
    {

        int l = 0;
        byte[] decryp_message;
        ArrayList<byte[]> d = new ArrayList<byte[]>();
        try {
            decryp_message = encryp_data;

            while(l < decryp_message.length)
            {
                byte[] len = new byte[4];
                System.arraycopy(decryp_message, l, len, 0, len.length);
                int L = ByteBuffer.wrap(len).getInt();

                byte[] dat = new byte[L];
                System.arraycopy(decryp_message, l+4, dat, 0, dat.length);
                d.add(dat);
                l = l + 4 + L;
            }
            if(l > decryp_message.length)
            {
                return null;
            }

            return d;
        }
        catch (Exception e)
        {
            System.out.println("Split Data failed");
            return null;
        }

    }

    //Getting the concatenated encrypted message
    protected  byte[] get_encrypted_concat_msg(int length,ArrayList<byte[]> data, CryptoAESProvider aes)
    {
        byte[] encrypt = new byte[length];
        int l = 0;

        for(int i=0; i<data.size(); i++)
        {
            byte[] d = ByteBuffer.allocate(4).putInt(data.get(i).length).array();
            byte[] gen = concatenateArrays(d,data.get(i));
            System.arraycopy(gen, 0, encrypt, l, gen.length);
            l = l + data.get(i).length + d.length;

        }

        try {
            return aes.encryptMessage(encrypt);
        }
        catch (Exception e)
        {
            System.out.println("Auth Data Encryption failed");
            return null;
        }

    }

    //Getting the split message in arraylist
    protected  ArrayList<byte[]> get_decrypted_split_msg(byte[] encryp_data, CryptoAESProvider aes)
    {

        int l = 0;
        byte[] decryp_message;
        ArrayList<byte[]> d = new ArrayList<byte[]>();
        try {
            decryp_message = aes.decryptMessage(encryp_data);

            while(l < decryp_message.length)
            {
                byte[] len = new byte[4];
                System.arraycopy(decryp_message, l, len, 0, len.length);
                int L = ByteBuffer.wrap(len).getInt();

                byte[] dat = new byte[L];
                System.arraycopy(decryp_message, l+4, dat, 0, dat.length);
                d.add(dat);
                l = l + 4 + L;
            }
            if(l > decryp_message.length)
            {
                return null;
            }

            return d;
        }
        catch (Exception e)
        {
            System.out.println("Split Data Decryption failed");
            return null;
        }

    }

    /**
     * To check the Timeout and return the message obtained
     * @return
     */
    protected String checkTimeout_getMessage(BufferedReader inStream)
    {
        String str = null;
        try{
            long startTime = System.currentTimeMillis();
            int timeout = 1000;
            while((str = inStream.readLine()) == null)
            {
                if(startTime + timeout < System.currentTimeMillis())
                {
                    return null;
                }
            }
            //str = inStream.readLine();

            return str;
        }
        catch (Exception e)
        {
            e.printStackTrace();
            return null;
        }
    }
}
