package com.zimbra.cs.account.auth;

/* loaded from: PasswordUtil.class */
public class PasswordUtil {
    public static void main(String[] args) {
        System.out.println("plain:        test123");
        System.out.println("encoded SSHA: " + SSHA.generateSSHA("test123", (byte[]) null));
        System.out.println("encoded SSHA512: " + SSHA512.generateSSHA512("test123", (byte[]) null));
        System.out.println("encoded SSH1: " + SHA1.generateSHA1("test123"));
        System.out.println("encoded MD5:  " + MD5.generateMD5("test123"));
        System.out.println();
        System.out.println("plain:        helloWorld");
        System.out.println("encoded SSHA: " + SSHA.generateSSHA("helloWorld", (byte[]) null));
        System.out.println("encoded SSHA512: " + SSHA512.generateSSHA512("helloWorld", (byte[]) null));
        System.out.println("encoded SSH1: " + SHA1.generateSHA1("helloWorld"));
        System.out.println("encoded MD5:  " + MD5.generateMD5("helloWorld"));
        System.out.println();
        String encodedSHA1 = SHA1.generateSHA1("testme", SHA1.access$000());
        String encodedSHA = SHA1.generateSHA1("testme", SHA1.access$100());
        boolean result = SHA1.verifySHA1(encodedSHA1, "testme");
        System.out.println("result is " + (result ? "good" : "bad"));
        boolean result2 = SHA1.verifySHA1(encodedSHA, "testme");
        System.out.println("result is " + (result2 ? "good" : "bad"));
    }
}