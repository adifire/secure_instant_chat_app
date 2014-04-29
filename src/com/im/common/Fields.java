package com.im.common;

import java.util.HashMap;

/**
 * Created by adityarao on 30/03/14.
 */
public class Fields {
    public String type;
    public String status;
    public HashMap<String, byte[]> data;

    public byte[] getUsername () {
        return data.get("username");
    }
}
