package com.im;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;

/**
 * Created by adityarao on 28/03/14.
 */
public class CryptoAESProvider {
    private static final String CHARSET = "UTF-8";
    private static final String RNG_ALGO = "SHA1PRNG";
    private static final String DIGEST_ALGO = "SHA-256";
    private static final String KEY_ALGO = "AES";
    private static final String CIPHER_ALGO = "AES/CBC/PKCS5Padding";

    private SecretKeySpec secretSpec;
    private IvParameterSpec ivSpec;
    private Cipher cipher;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public CryptoAESProvider () throws Exception {
        SecureRandom rnd = new SecureRandom();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128, rnd);
        SecretKey secretKey = keyGenerator.generateKey();
        secretSpec = new SecretKeySpec(secretKey.getEncoded(), KEY_ALGO);
        byte[] iv = new byte[16];
        rnd.nextBytes(iv);
        ivSpec = new IvParameterSpec(iv);
    }

    public CryptoAESProvider (byte[] secretKey) throws Exception {
        final MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGO);
        byte[] secret = new String (secretKey).getBytes(CHARSET);
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        System.arraycopy(secretKey, 0, key, 0, 16);
        System.arraycopy(secretKey, 16, iv, 0, 16);
        this.secretSpec = new SecretKeySpec(key, KEY_ALGO);
        this.ivSpec = new IvParameterSpec(iv);
    }

    public CryptoAESProvider (byte[] secretKey, byte[] iv) {
        this.secretSpec = new SecretKeySpec(secretKey, KEY_ALGO);
        this.ivSpec = new IvParameterSpec(iv);
    }

    public byte[] getIV () throws Exception {
        return ivSpec.getIV();
    }

    public byte[] getSecretKey () throws Exception {
        return secretSpec.getEncoded();
    }

    public byte[] encryptMessage (byte[] toEncrypt) throws Exception {
        cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.ENCRYPT_MODE, secretSpec, ivSpec);
        return new Base64().encode(cipher.doFinal(toEncrypt));
    }

    public byte[] decryptMessage (byte[] encryptedText) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
        cipher.init(Cipher.DECRYPT_MODE,secretSpec, ivSpec);
        return cipher.doFinal(new Base64().decode(encryptedText));
    }

}
