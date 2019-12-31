package aysEncDecSigEx;

import java.security.*;

public class RSA_SignVeri {

    /**
     * 数字签名/验证、
     */

    // 数字签名
    public static byte[] digitalsign(PrivateKey privateKey, String msg){
        byte[] data = msg.getBytes();
        try {
            Signature signature = Signature.getInstance("SHA384withRSA", "BCFIPS");
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    // 数字签名验证
    public static boolean signVertify(PublicKey publicKey, String msg, byte[] signmsg){
        byte[] data = msg.getBytes();
        try {
            Signature signature = Signature.getInstance("SHA384withRSA", "BCFIPS");
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(signmsg);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void main(String[] args) {
        RSA_Init rsa_init = new RSA_Init();
        KeyPair keyPair =  rsa_init.genKeypair(3072);
        // 可以分别获得公私密钥对
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        String msg = "this is a signature msg";

        byte[] signmsg = digitalsign(privateKey,msg);

        boolean res = signVertify(publicKey, msg, signmsg);

        if(res){
            System.out.println("签名验证成功");
        }else{
            System.out.println("签名验证失败");
        }
    }
}
