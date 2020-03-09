package org.hl7.cpcdsauthserver;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class PasswordUtils {

    /**
     * Generate a random string of length n for salting the password hash
     * 
     * @param n - length of the random string
     * @return a random string of length n
     */
    public static String generateSalt(int n) {
        byte[] salt = new byte[n];
        new Random().nextBytes(salt);
        return toHexString(salt);
    }

    /**
     * The SHA256 hash of the password using the given salt
     * 
     * @param password - the plain text password
     * @param salt     - the salt for the hash
     * @return Hash(password + salt)
     * @throws NoSuchAlgorithmException
     */
    public static String hashPassword(String password, String salt) {
        try {
            String p = password + salt;
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(p.getBytes(StandardCharsets.UTF_8));
            return toHexString(hash);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is a supported algorithm so this should never run
            System.out.println("PasswordUtils::hashPassword:SHA-256 is not a supported algorithm");
            return null;
        }
    }

    /**
     * Converts a byte array into hex chars
     * 
     * @param bytes - the byte array to convert
     * @return byte array as hex chars
     */
    private static String toHexString(byte[] bytes) {
        BigInteger number = new BigInteger(1, bytes);
        StringBuilder hexString = new StringBuilder(number.toString(16));
        while (hexString.length() < 32) {
            hexString.insert(0, '0');
        }
        return hexString.toString();
    }
}