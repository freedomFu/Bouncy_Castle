package aysEncDecSigEx;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

/**
 * 加解密
 */
public class RSA_EncDec {

    // 加密
    public static byte[] encrypt(PublicKey publicKey, String msg){

        byte[] data = msg.getBytes();
        try {
            Cipher c = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BCFIPS");
            c.init(Cipher.ENCRYPT_MODE, publicKey);

            return c.doFinal(data);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    // 解密
    public static byte[] decrypt(PrivateKey privateKey, byte[] cipherText){
        try {
            Cipher cipher = Cipher.getInstance("RSA/NONE/PKCS1Padding", "BCFIPS");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] res = cipher.doFinal(cipherText);
            return res;
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {
        RSA_Init rsa_init = new RSA_Init();
        KeyPair keyPair =  rsa_init.genKeypair(4096);
        // 可以分别获得公私密钥对
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String msg = "This is a test too";

        byte[] ciphermsg = encrypt(publicKey, msg);

        byte[] res = decrypt(privateKey,ciphermsg);

        if(null!=res){
            System.out.println("解密后的数据是："+new String(res));
        }else{
            System.out.println("出错了");
        }
    }

}
