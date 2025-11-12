package com.zimbra.cs.account.auth;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Base64;

/* loaded from: PasswordUtil$MD5.class */
public class PasswordUtil$MD5 {
    private static String MD5_ENCODING = "{MD5}";

    public static boolean isMD5(String encodedPassword) {
        return encodedPassword.startsWith(MD5_ENCODING);
    }

    public static boolean verifyMD5(String encodedPassword, String password) {
        if (!encodedPassword.startsWith(MD5_ENCODING)) {
            return false;
        }
        byte[] encodedBuff = encodedPassword.substring(MD5_ENCODING.length()).getBytes();
        Base64.decodeBase64(encodedBuff);
        String generated = generateMD5(password);
        return generated.equals(encodedPassword);
    }

    public static String generateMD5(String password) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(password.getBytes("UTF-8"));
            byte[] digest = md.digest();
            return MD5_ENCODING + new String(Base64.encodeBase64(digest));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e2) {
            throw new RuntimeException(e2);
        }
    }
}