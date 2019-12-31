package aysEncDecSigEx;

import java.security.*;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * 密钥产生、密钥交换
 */
public class RSA_Init {
    // 密钥产生 length指代密钥长度
    public KeyPair genKeypair(int length){
        Security.addProvider(new org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider());
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BCFIPS");
            keyPairGenerator.initialize(new RSAKeyGenParameterSpec(length,RSAKeyGenParameterSpec.F4));
            return keyPairGenerator.generateKeyPair();
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
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
    }
}
