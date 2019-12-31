package sysEncDec;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.swing.*;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;

/**
 * JCE AES Encryption and Decryption using CBC and PKCS5/7Padding
 */
public class AES {
    // 加密
    public static HashMap<String, byte[]> encrypt(String msg, SecretKey secretKey){
        HashMap<String, byte[]> encInfo = new HashMap<>(2);
        byte[] data = msg.getBytes();
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] iv = cipher.getIV();
            byte[] ciphertext = cipher.doFinal(data);
            encInfo.put("length",iv);
            encInfo.put("value",ciphertext);
            return encInfo;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    // 解密
    public static byte[] decrypt(SecretKey secretKey, byte[] iv, byte[] ciphertext) {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding", "BCFIPS");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
            byte[] res = cipher.doFinal(ciphertext);
            return res;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider());

        HashMap<String,byte[]> encInfo = new HashMap<>();
        String msg = "this is a test";
        try{
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES", "BCFIPS");
            keyGenerator.init(256);
            SecretKey aesKey = keyGenerator.generateKey();

            // 进行加密操作
            encInfo = encrypt(msg, aesKey);
            byte[] iv = encInfo.get("length");
            byte[] cipherdata = encInfo.get("value");
            //System.out.println("加密后的数据是"+new String(cipherdata));

            // 进行解密操作
            byte[] res = decrypt(aesKey,iv,cipherdata);
            System.out.println("解密后的数据是："+new String(res));
        } catch (NoSuchAlgorithmException | NoSuchProviderException e1){
            e1.printStackTrace();
        }
    }

}
