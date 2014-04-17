package com.im;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by adityarao on 28/03/14.
 */
public class CryptoRSAProvider {
    private KeyPair keyPair;
    private PublicKey serverPublicKey;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public CryptoRSAProvider () {}

    public CryptoRSAProvider (int size) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(size);
        keyPair = keyGen.generateKeyPair();
    }

    public CryptoRSAProvider (String pubFileName, String privFileName) throws Exception {
        File f = new File(privFileName);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();

        PKCS8EncodedKeySpec spec =
                new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        f = new File(pubFileName);
        fis = new FileInputStream(f);
        dis = new DataInputStream(fis);
        keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
        keyPair = new KeyPair(keyFactory.generatePublic(pubSpec), keyFactory.generatePrivate(spec));
    }

    public void setServerPublicKey (String pubFileName) throws Exception {
        File f = new File(pubFileName);
        FileInputStream fis = new FileInputStream(f);
        DataInputStream dis = new DataInputStream(fis);
        byte[] keyBytes = new byte[(int)f.length()];
        dis.readFully(keyBytes);
        dis.close();
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
        this.serverPublicKey = keyFactory.generatePublic(pubSpec);
    }

    public static PublicKey getPublicKey (byte[] pubBytes) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(pubBytes);
        return keyFactory.generatePublic(pubSpec);
    }


    public PublicKey getPublicKey () {
        return keyPair.getPublic();
    }

    public PublicKey getServerPublicKey () {
        return this.serverPublicKey;
    }

    public static byte[] encryptText (byte[] plainText, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");

        cipher.init(Cipher.ENCRYPT_MODE, key);

        return new Base64().encode(cipher.doFinal(plainText));
    }

    public byte[] decryptText (byte[] encryptedText) throws Exception{
        if (keyPair == null)
            return null;
        Cipher cipher = Cipher.getInstance("RSA/None/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        return cipher.doFinal(new Base64().decode(encryptedText));
    }

    public byte[] signText (byte[] toSigned) throws Exception {
        if (keyPair == null)
            return null;
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(toSigned);
        return signature.sign();
    }

    public static boolean verifyText (byte[] toVerify, byte[] mac, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(publicKey);
        signature.update(toVerify);
        return signature.verify(mac);
    }
}
