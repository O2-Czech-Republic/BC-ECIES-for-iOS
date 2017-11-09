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
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
import org.bouncycastle.util.encoders.Base64;

import java.security.KeyFactory;
import java.security.SecureRandom;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.Cipher;

public class Main {

    public Main() {}

    private static String PUBLIC_KEY = "BBaPTE9w7+XA0bH0bmoqBou7ieI/AP/Yzx8JoAYxB11XgpoiRqnlSySa9lF5dzU7meKvN8TlX1bybUZTtqljCJw=";
    private static String PRIVATE_KEY = "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4eSgzxefv1TF8LRy3M0DI5MkQ6+HCqVBxLtJOEovV3ChRANCAAQLKgQxt5HmRvEWTZ9jMvZTNT2ANsI74wv2U6kdR1l7KxAqOckjpgbrWGfmKvkOkIMy001gRSafMV/X6mOkxjXo";

    public static void main( String[] args )
    {

        try {

            // This produces ciphertext that can be decrypted by calling
            // `SecKeyCreateDecryptedData` on iOS
            String plaintext = "test";
            System.out.println("======== Encrypting message:   " + plaintext);
            String encryptedPlaintext = testEncrypt(plaintext);
            System.out.println("======== Ciphertext:           " + encryptedPlaintext);

            // This ciphertext was produced by Apple's `SecKeyCreateDecryptedData`
            // method
            String ciphertext = "BDoUkNsU4RC8SSjrwOtDi8TEZuq09Zz/q7/YWKbBt44fLKDDlIm7Nq4OF66AiUIzX/sXpxuysdCHoEuINt2LAise8TbddzI3vbgLGaoD2ttj0O8LtA==";
            System.out.println("======== Decrypting message:   " + ciphertext);
            String decryptedCiphertext = testDecrypt(ciphertext);
            System.out.println("======== Plaintext:            " + decryptedCiphertext);

        }
        catch (Exception e) {
            e.printStackTrace();
        }

    }

    public static String testEncrypt (String plaintext) throws Exception {

        byte[] publicKey = Base64.decode(PUBLIC_KEY);
        return encrypt(plaintext, publicKey, "secp256r1");

    }

    public static String testDecrypt (String ciphertext) throws Exception {

        byte[] privateKey = Base64.decode(PRIVATE_KEY);
        return decrypt(ciphertext, privateKey);

    }


    private static String encrypt(String plaintext, byte[] publicKeyBytes, String curveName) throws Exception {

        org.bouncycastle.jce.spec.ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curveName);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.spec.ECNamedCurveSpec curvedParams = new ECNamedCurveSpec(curveName, spec.getCurve(), spec.getG(), spec.getN());
        java.security.spec.ECPoint point = org.bouncycastle.jce.ECPointUtil.decodePoint(curvedParams.getCurve(), publicKeyBytes);
        java.security.spec.ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, curvedParams);
        org.bouncycastle.jce.interfaces.ECPublicKey publicKey = (ECPublicKey) keyFactory.generatePublic(pubKeySpec);

        byte[] inputBytes = plaintext.getBytes();

        org.bouncycastle.jce.spec.IESParameterSpec params = new IESParameterSpec(null, null, 0, 128, new byte[16]);
        IESCipherGCM cipher = new IESCipherGCM(
                new IESEngineGCM(
                        new ECDHBasicAgreement(),
                        new KDF2BytesGenerator(new SHA256Digest()),
                        new AESGCMBlockCipher()), 16);

        cipher.engineInit(Cipher.ENCRYPT_MODE, publicKey, params, new SecureRandom());

        byte[] cipherResult = cipher.engineDoFinal(inputBytes, 0, inputBytes.length);
        return Base64.toBase64String(cipherResult);
    }


    private static String decrypt(String ciphertext, byte[] privateKeyBytes) throws Exception {

        java.security.spec.PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        org.bouncycastle.jce.interfaces.ECPrivateKey privateKey = (ECPrivateKey) keyFactory.generatePrivate(encodedKeySpec);

        byte[] inputBytes = Base64.decode(ciphertext);

        IESParameterSpec params = new IESParameterSpec(null, null, 0, 128, new byte[16]);
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
