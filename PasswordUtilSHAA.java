package com.zimbra.cs.account.auth;

import com.zimbra.cs.ldap.unboundid.InMemoryLdapServer;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import org.apache.commons.codec.binary.Base64;

/* loaded from: PasswordUtil$SSHA.class */
public class PasswordUtil$SSHA {
    private static int SALT_LEN = 4;
    private static String SSHA_ENCODING = "{SSHA}";

    public static boolean isSSHA(String encodedPassword) {
        return encodedPassword.startsWith(SSHA_ENCODING);
    }

    public static boolean verifySSHA(String encodedPassword, String password) {
        if (!encodedPassword.startsWith(SSHA_ENCODING)) {
            return false;
        }
        byte[] encodedBuff = encodedPassword.substring(SSHA_ENCODING.length()).getBytes();
        byte[] buff = Base64.decodeBase64(encodedBuff);
        if (buff.length <= SALT_LEN) {
            return false;
        }
        int slen = buff.length == 28 ? 8 : SALT_LEN;
        byte[] salt = new byte[slen];
        System.arraycopy(buff, buff.length - slen, salt, 0, slen);
        String generated = generateSSHA(password, salt);
        return generated.equals(encodedPassword);
    }

    public static String generateSSHA(String password, byte[] salt) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            if (salt == null) {
                if (InMemoryLdapServer.isOn()) {
                    salt = new byte[]{127, 127, 127, 127};
                } else {
                    salt = new byte[SALT_LEN];
                    SecureRandom sr = new SecureRandom();
                    sr.nextBytes(salt);
                }
            }
            md.update(password.getBytes("UTF-8"));
            md.update(salt);
            byte[] digest = md.digest();
            byte[] buff = new byte[digest.length + salt.length];
            System.arraycopy(digest, 0, buff, 0, digest.length);
            System.arraycopy(salt, 0, buff, digest.length, salt.length);
            return SSHA_ENCODING + new String(Base64.encodeBase64(buff));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e2) {
            throw new RuntimeException(e2);
        }
    }
}