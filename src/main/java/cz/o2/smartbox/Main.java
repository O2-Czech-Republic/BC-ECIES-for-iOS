package cz.o2.smartbox;

import cz.o2.smartbox.crypto.ecies.AESGCMBlockCipher;
import cz.o2.smartbox.crypto.ecies.IESCipherGCM;
import cz.o2.smartbox.crypto.ecies.IESEngineGCM;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.KDF2BytesGenerator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Base64;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

public class Main {

    private static String PEER_PUBLIC_KEY = "BMgQBKP98y4zREWNUn+j1f5aiM8kA2h0Hy055H/vLtDIDM7b7AQGDsUrIPbqQUSDPveQCN4/OZjUC8Ji/7oXQVs=\n";

    public static void main( String[] args ) {
        Main m = new Main();
    }

    public Main () {

        try {

            /*
            ECNamedCurveParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
            g.initialize(ecSpec, new SecureRandom());
            KeyPair pair = g.generateKeyPair();
            ECPrivateKey privateKey = (ECPrivateKey) pair.getPrivate();
            ECPublicKey publicKey = (ECPublicKey) pair.getPublic();

            System.out.println("======== Generated public key:  " + Base64.toBase64String(publicKey.getEncoded()));
            System.out.println("======== Generated private key: " + Base64.toBase64String(privateKey.getEncoded()));
            */

            // This produces ciphertext that can be decrypted by calling
            // `SecKeyCreateDecryptedData` on iOS
            String plaintext = "test";
            System.out.println("======== Encrypting message:    " + plaintext);
            String encryptedPlaintext = testEncrypt(plaintext, PEER_PUBLIC_KEY);
            System.out.println("======== Ciphertext:            " + encryptedPlaintext);

            // This ciphertext was produced by Apple's `SecKeyCreateDecryptedData`
            // method using the following public key data:
            // MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+E1qHuq3h1Z/wlZhV9eJMLyZTlm6hFR/A5grmnMNCkN7kzCQcWfgaa0vw24mFk20AyF6G6EX/lxyxZZjFQWaJA==
            String ciphertext = "BAfx2IcjzCaggrAF76ztZDAJzaEfJFGgSyVsqt3MsXmxhRtiPVHRkh3VIjeUB+fPSyoI5xJ0+Bjq4uQgJ1GtkFx/zLiR/LSf/UBgzkkPPDBXXdQDKjcS";
            String privateKey = "MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgCIkUy+DMVJDPhHQwS1lCrT/72qcz0vFWinZf3Gl0g5OgCgYIKoZIzj0DAQehRANCAAT4TWoe6reHVn/CVmFX14kwvJlOWbqEVH8DmCuacw0KQ3uTMJBxZ+BprS/DbiYWTbQDIXoboRf+XHLFlmMVBZok";
            System.out.println("======== Decrypting message:    " + ciphertext);
            String decryptedCiphertext = testDecrypt(ciphertext, privateKey);
            System.out.println("======== Plaintext:             " + decryptedCiphertext);

        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    public String testEncrypt (String plaintext, String peerPublicKey) throws Exception {

        byte[] publicKey = Base64.decode(peerPublicKey);
        return encrypt(plaintext, publicKey, "secp256r1");

    }

    public String testDecrypt (String ciphertext, String ownPrivateKey) throws Exception {

        byte[] privateKey = Base64.decode(ownPrivateKey);
        return decrypt(ciphertext, privateKey);

    }


    private String encrypt(String plaintext, byte[] publicKeyBytes, String curveName) throws Exception {

        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECNamedCurveSpec curvedParams = new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN());
        java.security.spec.ECPoint point = org.bouncycastle.jce.ECPointUtil.decodePoint(curvedParams.getCurve(), publicKeyBytes);
        java.security.spec.ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, curvedParams);
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);

        byte[] inputBytes = plaintext.getBytes();

        org.bouncycastle.jce.spec.IESParameterSpec params = new IESParameterSpec(null, null, 128, 128, null);
        IESCipherGCM cipher = new IESCipherGCM(
                new IESEngineGCM(
                        new ECDHBasicAgreement(),
                        new KDF2BytesGenerator(new SHA256Digest()),
                        new AESGCMBlockCipher()), 16);

        cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey, params, new SecureRandom());

        byte[] cipherResult = cipher.engineDoFinal(inputBytes, 0, inputBytes.length);
        return Base64.toBase64String(cipherResult);
    }


    private String decrypt(String ciphertext, byte[] privateKeyBytes) throws Exception {

        java.security.spec.PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.interfaces.ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(encodedKeySpec);

        byte[] inputBytes = Base64.decode(ciphertext);

        IESParameterSpec params = new IESParameterSpec(null, null, 128, 128, null);
        IESCipherGCM cipher = new IESCipherGCM(
                new IESEngineGCM(
                        new ECDHBasicAgreement(),
                        new KDF2BytesGenerator(new SHA256Digest()),
                        new AESGCMBlockCipher()), 16);

        cipher.engineInit(Cipher.DECRYPT_MODE, privateKey, params, new SecureRandom());

        byte[] cipherResult = cipher.engineDoFinal(inputBytes, 0, inputBytes.length);
        return new String(cipherResult);

    }

}
