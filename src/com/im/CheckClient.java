package com.im;

import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

/**
 * Created by Yogesh on 4/8/2014.
 * To Check for clients which are not talking for a long time
 * We will remove there information from the ClientChat
 */
public class CheckClient extends Thread{
    ClientChat cl_chat;
    public CheckClient(ClientChat cl)
    {
        this.cl_chat = cl;
    }

    public void run()
    {
        try{
            while(true){
                Thread.sleep(6000);
                HashMap<String, ClientTalkDetails> userConnected;
                synchronized (cl_chat.usersConnected) {
                     userConnected = cl_chat.usersConnected;
                }
                Iterator it = userConnected.entrySet().iterator();
                while (it.hasNext()) {
                    ClientTalkDetails c1 = (ClientTalkDetails)((Map.Entry)it.next()).getValue();
                    if(check_timestamp(c1)) {
                        System.out.println("Disconnecting user: " + c1.getUser());
                        synchronized (cl_chat.usersConnected) {
                            cl_chat.usersConnected.remove(c1.getUser());
                        }
                    }
                }
            }
        }
        catch (Exception e)
        {
            e.printStackTrace();
            System.out.println("Exiting from CheckClient Thread");
        }

    }

    private boolean check_timestamp(ClientTalkDetails ctalk)
    {
        Timestamp t = ctalk.getTime();
        long savedMil = t.getTime();
        long curMil = System.currentTimeMillis();
        return ((savedMil + 60000) < curMil);
    }
}
