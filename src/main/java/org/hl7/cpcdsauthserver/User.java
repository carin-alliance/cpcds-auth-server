package org.hl7.cpcdsauthserver;

import java.util.HashMap;
import java.util.Map;

public class User {

    private String r;
    private String id;
    private String username;
    private String password;
    private String createdDate;

    public User(String username, String password, String id, String r) {
        this(username, password, id, r, null);
    }

    public User(String username, String password, String id, String r, String createdDate) {
        this.r = r;
        this.password = password;
        this.id = id;
        this.username = username;
        this.createdDate = createdDate;
    }

    public String getR() {
        return this.r;
    }

    public String getId() {
        return this.id;
    }

    public String getUsername() {
        return this.username;
    }

    public String getPassword() {
        return this.password;
    }

    public String getCreatedDate() {
        return this.createdDate;
    }

    public Map<String, Object> toMap() {
        HashMap<String, Object> map = new HashMap<String, Object>();
        map.put("username", this.username);
        map.put("password", this.password);
        map.put("id", this.id);
        map.put("r", this.r);
        return map;
    }

    /**
     * Validate the input password is a match to the stored hashed password
     * 
     * @param input - plain text input password
     * @return true if input is the correct password for this user, false otherwise
     */
    public boolean validatePassword(String input) {
        // Validate Hash(input + r) = password
        return false;
    }

    @Override
    public String toString() {
        return "User " + this.username + "(" + this.id + "): password(" + this.password + ")";
    }
}