package com.zimbra.cs.account.auth;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.apache.commons.codec.binary.Base64;

/* loaded from: PasswordUtil$SHA1.class */
public class PasswordUtil$SHA1 {
    private static String SHA1_ENCODING = "{SHA1}";
    private static String SHA_ENCODING = "{SHA}";

    public static boolean isSHA1(String encodedPassword) {
        return encodedPassword.startsWith(SHA1_ENCODING) || encodedPassword.startsWith(SHA_ENCODING);
    }

    public static boolean verifySHA1(String encodedPassword, String password) {
        String prefix;
        String str = SHA1_ENCODING;
        if (encodedPassword.startsWith(SHA1_ENCODING)) {
            prefix = SHA1_ENCODING;
        } else if (encodedPassword.startsWith(SHA_ENCODING)) {
            prefix = SHA_ENCODING;
        } else {
            return false;
        }
        byte[] encodedBuff = encodedPassword.substring(prefix.length()).getBytes();
        Base64.decodeBase64(encodedBuff);
        String generated = generateSHA1(password, prefix);
        return generated.equals(encodedPassword);
    }

    public static String generateSHA1(String password) {
        return generateSHA1(password, SHA1_ENCODING);
    }

    public static String generateSHA1(String password, String prefix) {
        if (prefix == null) {
            prefix = SHA1_ENCODING;
        }
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            md.update(password.getBytes("UTF-8"));
            byte[] digest = md.digest();
            return prefix + new String(Base64.encodeBase64(digest));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e2) {
            throw new RuntimeException(e2);
        }
    }
}