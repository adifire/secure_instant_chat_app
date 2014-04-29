package com.im.server;

import com.im.common.HelperFunc;

import java.io.*;
import java.util.*;

/**
 * Created by adityarao on 4/4/14.
 */
public class HandleUserData {

    /*
        This should be done one time. Provide a hash map of usernames and corresponding passwords
        and the data will be stored in the file specified by filename parameter
     */
    public static boolean generateUserData(String filename, HashMap<String, String> users) {
        File userDat = new File(filename);
        try {
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(new FileOutputStream(userDat));

            Hashtable<String, SaltPwdPair> new_users = new Hashtable<String, SaltPwdPair>();

            Iterator iterator = users.entrySet().iterator();

            while (iterator.hasNext()) {
                Map.Entry<String, String> entry = (Map.Entry<String, String>) iterator.next();
                byte[] salt = HelperFunc.generateSalt();
                byte[] hashedPwd = HelperFunc.generate_pwdHash(entry.getValue().getBytes(), salt);
                SaltPwdPair saltPwdPair = new SaltPwdPair(salt, hashedPwd);
                new_users.put(entry.getKey(), saltPwdPair);
            }

            objectOutputStream.writeObject(new_users);
            objectOutputStream.close();
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    /*
        Checks whether the user is present in the user data store
     */
    public boolean findUser (String username) {
        synchronized (users) {
            return users.containsKey(username);
        }
    }

    /*
        Get the salt for the corresponding user
     */
    public byte[] getSalt (String username) {
        synchronized (users) {
            if (users.containsKey(username)) {
               return users.get(username).getSalt();
            }
        }
        return null;
    }

    /*
        Validate the user with given salted hash of password.
        Make sure the password is salted and hashed.
     */
    public boolean validateUser (String username, byte[] password) {
        synchronized (users) {
            if (users.containsKey(username)) {
                return users.get(username).comparePwd(password);
            }
        }
        return false;
    }

    /*
        Pass the filename of the user data store
     */
    public HandleUserData(String userDataStoreFileName) {
        File userDSFile = new File(userDataStoreFileName);
        try {
            ObjectInputStream in = new ObjectInputStream(new FileInputStream(userDSFile));
            this.users = (Hashtable) in.readObject();
            if (this.users == null)
                System.out.println("No data found on the user data file");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
            return;
        } catch (IOException e) {
            e.printStackTrace();
            return;
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }

    public void showUsers() {
        Iterator iterator = this.users.entrySet().iterator();
        while (iterator.hasNext()) {
            System.out.println(((Map.Entry<String, SaltPwdPair>) iterator.next()).getKey());
        }
    }

    private static Hashtable<String, SaltPwdPair> users;

    public static class SaltPwdPair implements Serializable {


        public SaltPwdPair (byte[] salt, byte[] password) {
            this.salt = salt;
            this.password = password;
        }

        private byte[] salt;
        private byte[] password;

        private static final long serialVersionUID = 7526472295622776147L;

        public byte[] getSalt() {
            return salt;
        }

        public boolean comparePwd (byte[] checkPwd) {
            if (checkPwd.length == this.password.length) {
                return Arrays.equals(checkPwd, this.password);
            }
            return false;
        }
    }
}
