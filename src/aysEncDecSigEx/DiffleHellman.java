package aysEncDecSigEx;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.security.auth.callback.TextInputCallback;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;

public class DiffleHellman {
    //生成参数
    public static DHParameterSpec DHParameterGen(int length){
        try {
            AlgorithmParameterGenerator algorithmParameterGenerator = AlgorithmParameterGenerator.getInstance("DH", "BCFIPS");
            algorithmParameterGenerator.init(length);

            AlgorithmParameters dsaParams = algorithmParameterGenerator.generateParameters();
            return dsaParams.getParameterSpec(DHParameterSpec.class);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidParameterSpecException e) {
            e.printStackTrace();
        }
        return null;
    }
    //产生密钥对
    public static KeyPair generKeyPair(DHParameterSpec dhParameterSpec){
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH", "BCFIPS");
            keyPairGenerator.initialize(dhParameterSpec);
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }

    //密钥协商过程  双方都需要
    public static byte[] initorAgreement(PrivateKey initPrivateKey, PublicKey recvPublicKey){
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("DH", "BCFIPS");
            agreement.init(initPrivateKey);
            agreement.doPhase(recvPublicKey,true);

            SecretKey agreeKey = agreement.generateSecret("AES[256]");

            return agreeKey.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static byte[] recvAgreement(PrivateKey recvPrivateKey, PublicKey initPublicKey){
        try {
            KeyAgreement agreement = KeyAgreement.getInstance("DH", "BCFIPS");
            agreement.init(recvPrivateKey);
            agreement.doPhase(initPublicKey,true);

            SecretKey agreeKey = agreement.generateSecret("AES[256]");

            return agreeKey.getEncoded();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }


    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider());

        DHParameterSpec dhParameterSpec1 = DHParameterGen(3072);

        KeyPair initKeyPair = generKeyPair(dhParameterSpec1);
        KeyPair recvKeyPair = generKeyPair(dhParameterSpec1);
        // 查看地址
        System.out.println(initKeyPair);
        System.out.println(recvKeyPair);

        if(null!=initKeyPair && null!=recvKeyPair){
            PrivateKey initPrivateKey = initKeyPair.getPrivate();
            PublicKey initPublicKey = initKeyPair.getPublic();
            PrivateKey recvPrivateKey = recvKeyPair.getPrivate();
            PublicKey recvPublicKey = recvKeyPair.getPublic();

            // 协商过程
            byte[] initagreeKey = initorAgreement(initPrivateKey,recvPublicKey);
            byte[] recvagreeKey = recvAgreement(recvPrivateKey,initPublicKey);
            BigInteger initbigInteger = new BigInteger(1, initagreeKey);
            BigInteger recvbigInteger = new BigInteger(1, recvagreeKey);
            System.out.println("init方："+initbigInteger.toString(16));
            System.out.println("recv方："+recvbigInteger.toString(16));
        }else{
            System.out.println("出错了");
            return;
        }
    }
}
