package com.im;

import java.net.InetAddress;
import java.security.PublicKey;

/**
 * Created by adityarao on 4/5/14.
 */
public class ClientDetails {

    private ClientDetails () {}

    public ClientDetails (String username, InetAddress inetAddress, int port, PublicKey publicKey, CryptoAESProvider aes) {
        this.username = username;
        this.inetAddress = inetAddress;
        this.port = port;
        this.publicKey = publicKey;
        this.aes = aes;
    }

    public InetAddress getInetAddress() {
        return inetAddress;
    }

    public String getUsername() {
        return username;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public CryptoAESProvider getAESProvider() { return aes; }

    public int getPort() {
        return port;
    }

    private String username;
    private InetAddress inetAddress;
    private int port;
    private PublicKey publicKey;
    private CryptoAESProvider aes;
}
