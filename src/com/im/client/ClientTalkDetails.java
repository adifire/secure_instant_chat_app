package com.im.client;

import com.im.common.HelperFunc;
import com.im.cyptoprovider.CryptoAESProvider;

import java.net.InetAddress;
import java.security.PublicKey;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Arrays;

/**
 * Created by Yogesh on 4/6/2014.
 */
public class ClientTalkDetails {

    private ClientTalkDetails () {}

    public ClientTalkDetails (String user, byte[] ticket, InetAddress inetAddress, int port,
                              PublicKey publicKey, byte[] timestamp, byte[] nonce, byte[] signedNonce) {
        this.user = user;
        this.ticket = ticket;
        this.inetAddress = inetAddress;
        this.port = port;
        this.publicKey = publicKey;
        this.timestamp = timestamp;
        this.initialNonce = nonce;
        this.signedNonce = signedNonce;
        java.util.Date date= new java.util.Date();
        Timestamp t = new Timestamp(date.getTime());
        this.last_request = t;
    }

    public InetAddress getInetAddress() {
        return inetAddress;
    }

    public byte[] getTicket() {
        return ticket;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public byte[] getTimestamp() {
        return timestamp;
    }

    public byte[] generateSecretKey() {
        try {
            this.aesProvider = new CryptoAESProvider();
            return this.aesProvider.getSecretKey();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public byte[] getIV() {
        try {
            return this.aesProvider.getIV();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public int getPort() {
        return port;
    }

    public byte[] getInitialNonce() {
        return this.initialNonce;
    }

    public boolean isLoggedOut() {
        return loggedOut;
    }

    public void setLoggedOut(boolean loggedOut) {
        this.loggedOut = loggedOut;
    }

    public byte[] getSignedNonce() {
        return signedNonce;
    }

    public boolean isLoggingIn() {
        return loggingIn;
    }

    public void setLoggingIn(boolean loggingIn) {
        this.loggingIn = loggingIn;
    }

    public String getUser() {
        return user;
    }

    public void setUser(String user) {
        this.user = user;
    }

    public CryptoAESProvider getAesProvider() {
        return aesProvider;
    }

    public void setAesProvider(CryptoAESProvider aesProvider) {
        this.aesProvider = aesProvider;
    }

    public byte[] generateNonce() {
        byte[] nonce = HelperFunc.generateNonce();
        while (nonce != null && this.nonces.contains(nonce))
            nonce = HelperFunc.generateNonce();
        this.nonces.add(nonce);
        try {
            return nonce;
            //return this.getAesProvider().encryptMessage(nonce);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean appendNonce (byte[] nonce) {
        if (!this.otherNonces.contains(nonce))
            return this.otherNonces.add(nonce);
        return false;
    }

    public boolean checkNonce (byte[] nonce) {
        return Arrays.equals(this.nonces.get(this.nonces.size()-1), HelperFunc.inc_Nonce(nonce));
    }

    public byte[] getLastNonceDec () throws Exception {
        return HelperFunc.dec_Nonce(this.otherNonces.get(this.otherNonces.size() - 1));
    }

    public void setTime()
    {
        java.util.Date date= new java.util.Date();
        Timestamp t = new Timestamp(date.getTime());
        this.last_request = t;
    }

    public Timestamp getTime()
    {
        return last_request;
    }

    public void setDisconnect(Boolean b)
    {
        sent_disconnect = b;
    }

    public boolean getDisconnect()
    {
        return sent_disconnect;
    }

    private String user;
    private byte[] ticket;
    private InetAddress inetAddress;
    private int port;
    private PublicKey publicKey;
    private byte[] timestamp;
    private CryptoAESProvider aesProvider;
    private byte[] initialNonce, signedNonce;
    private ArrayList<byte[]> nonces = new ArrayList<byte[]>(), otherNonces = new ArrayList<byte[]>();
    private boolean loggedOut, loggingIn;
    public String initialMessage;
    private Timestamp last_request;
    private boolean sent_disconnect=false;
}
