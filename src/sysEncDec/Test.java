package sysEncDec;

import org.bouncycastle.crypto.fips.FipsOutputEncryptor;

import javax.crypto.*;

public class Test {
    public static final String stringToEncrypt="This is a test.";
    public static void main(String[] args) throws Exception {

        System.out.print("Attempting to get a Blowfish key...");
        KeyGenerator keyGenerator=KeyGenerator.getInstance("Blowfish");
        keyGenerator.init(128);
        SecretKey key=keyGenerator.generateKey();

        System.out.println("OK");
        System.out.println("Attempting to get a Cipher and encrypt...");
        Cipher cipher=Cipher.getInstance("Blowfish/ECB/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE,key);

        byte[] cipherText=cipher.doFinal(stringToEncrypt.getBytes("UTF8"));
        System.out.println(cipherText);
        System.out.println("OK");

        System.out.println("Test completed successfully.");
    }
}
