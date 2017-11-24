package cz.o2.smartbox.crypto.ecies;

import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DerivationFunction;
import org.bouncycastle.crypto.EphemeralKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyParser;
import org.bouncycastle.crypto.generators.EphemeralKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Base64;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;


public class IESEngineGCM {
    BasicAgreement agree;
    DerivationFunction kdf;
    BufferedBlockCipher cipher;

    boolean forEncryption;
    CipherParameters privParam, pubParam;
    IESParameters param;

    byte[] encodedPublicKey;
    private EphemeralKeyPairGenerator keyPairGenerator;
    private KeyParser keyParser;
    private byte[] IV;

    /**
     * set up for use with stream mode, where the key derivation function
     * is used to provide a stream of bytes to xor with the message.
     *
     * @param agree the key agreement used as the basis for the encryption
     * @param kdf   the key derivation function used for byte generation
     */
    public IESEngineGCM(
            BasicAgreement agree,
            DerivationFunction kdf)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.cipher = null;
    }


    /**
     * set up for use in conjunction with a block cipher to handle the
     * message.
     *
     * @param agree  the key agreement used as the basis for the encryption
     * @param kdf    the key derivation function used for byte generation
     * @param cipher the cipher to used for encrypting the message
     */
    public IESEngineGCM(
            BasicAgreement agree,
            DerivationFunction kdf,
            BufferedBlockCipher cipher)
    {
        this.agree = agree;
        this.kdf = kdf;
        this.cipher = cipher;
    }

    /**
     * Initialise the encryptor.
     *
     * @param forEncryption whether or not this is encryption/decryption.
     * @param privParam     our private key parameters
     * @param pubParam      the recipient's/sender's public key parameters
     * @param params        encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
     */
    public void init(
            boolean forEncryption,
            CipherParameters privParam,
            CipherParameters pubParam,
            CipherParameters params)
    {
        this.forEncryption = forEncryption;
        this.privParam = privParam;
        this.pubParam = pubParam;
        this.encodedPublicKey = new byte[0];

        extractParams(params);
    }

    /**
     * Initialise the decryptor.
     *
     * @param publicKey      the recipient's/sender's public key parameters
     * @param params         encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
     * @param ephemeralKeyPairGenerator             the ephemeral key pair generator to use.
     */
    public void init(AsymmetricKeyParameter publicKey, CipherParameters params, EphemeralKeyPairGenerator ephemeralKeyPairGenerator)
    {
        this.forEncryption = true;
        this.pubParam = publicKey;
        this.keyPairGenerator = ephemeralKeyPairGenerator;

        extractParams(params);
    }

    /**
     * Initialise the encryptor.
     *
     * @param privateKey      the recipient's private key.
     * @param params          encoding and derivation parameters, may be wrapped to include an IV for an underlying block cipher.
     * @param publicKeyParser the parser for reading the ephemeral public key.
     */
    public void init(AsymmetricKeyParameter privateKey, CipherParameters params, KeyParser publicKeyParser)
    {
        this.forEncryption = false;
        this.privParam = privateKey;
        this.keyParser = publicKeyParser;

        extractParams(params);
    }

    private void extractParams(CipherParameters params)
    {
        if (params instanceof ParametersWithIV)
        {
            this.IV = ((ParametersWithIV)params).getIV();
            this.param = (IESParameters)((ParametersWithIV)params).getParameters();
        }
        else
        {
            this.IV = null;
            this.param = (IESParameters)params;
        }
    }

    public BufferedBlockCipher getCipher()
    {
        return cipher;
    }

    private byte[] encryptBlock(
            byte[] in,
            int inOff,
            int inLen)
            throws InvalidCipherTextException
    {
        byte[] C = null, K = null, K1 = null, K2 = null;
        int len;

        if (cipher == null)
        {
            // Streaming mode.
            K1 = new byte[inLen];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);

            if (encodedPublicKey.length != 0)
            {
                System.arraycopy(K, 0, K2, 0, K2.length);
                System.arraycopy(K, K2.length, K1, 0, K1.length);
            }
            else
            {
                System.arraycopy(K, 0, K1, 0, K1.length);
                System.arraycopy(K, inLen, K2, 0, K2.length);
            }

            C = new byte[inLen];

            for (int i = 0; i != inLen; i++)
            {
                C[i] = (byte)(in[inOff + i] ^ K1[i]);
            }
            len = inLen;
        }
        else
        {
            // Block cipher mode.
            K1 = new byte[((IESWithCipherParameters)param).getCipherKeySize() / 8];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);
            System.arraycopy(K, 0, K1, 0, K1.length);
            System.arraycopy(K, K1.length, K2, 0, K2.length);

            // If iv provided use it to initialise the cipher
            if (IV != null)
            {
                cipher.init(true, new ParametersWithIV(new KeyParameter(K1), IV));
            }
            else
            {
                cipher.init(true, new ParametersWithIV(new KeyParameter(K1), K2));
            }

            C = new byte[cipher.getOutputSize(inLen)];
            len = cipher.processBytes(in, inOff, inLen, C, 0);
            len += cipher.doFinal(C, len);
        }


        // Output the triple (encodedPublicKey,C,T).
        byte[] Output = new byte[encodedPublicKey.length + len];
        System.arraycopy(encodedPublicKey, 0, Output, 0, encodedPublicKey.length);
        System.arraycopy(C, 0, Output, encodedPublicKey.length, len);
        return Output;
    }

    private byte[] decryptBlock(
            byte[] in_enc,
            int inOff,
            int inLen)
            throws InvalidCipherTextException
    {
        byte[] M = null, K = null, K1 = null, K2 = null;
        int len;

        // Ensure that the length of the input is greater than the public key
        if (inLen < encodedPublicKey.length)
        {
            throw new InvalidCipherTextException("Length of input must be greater than the MAC and encodedPublicKey combined");
        }

        if (cipher == null)
        {
            // Streaming mode.
            K1 = new byte[inLen - encodedPublicKey.length];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);

            if (encodedPublicKey.length != 0)
            {
                System.arraycopy(K, 0, K2, 0, K2.length);
                System.arraycopy(K, K2.length, K1, 0, K1.length);
            }
            else
            {
                System.arraycopy(K, 0, K1, 0, K1.length);
                System.arraycopy(K, K1.length, K2, 0, K2.length);
            }

            M = new byte[K1.length];

            for (int i = 0; i != K1.length; i++)
            {
                M[i] = (byte)(in_enc[inOff + encodedPublicKey.length + i] ^ K1[i]);
            }

            len = K1.length;
        }
        else
        {
            // Block cipher mode.
            K1 = new byte[((IESWithCipherParameters)param).getCipherKeySize() / 8];
            K2 = new byte[param.getMacKeySize() / 8];
            K = new byte[K1.length + K2.length];

            kdf.generateBytes(K, 0, K.length);
            System.arraycopy(K, 0, K1, 0, K1.length);
            System.arraycopy(K, K1.length, K2, 0, K2.length);

            // If IV provide use it to initialize the cipher
            if (IV != null)
            {
                cipher.init(false, new ParametersWithIV(new KeyParameter(K1), IV));
            }
            else
            {
                cipher.init(false, new ParametersWithIV(new KeyParameter(K1), K2));
            }

            M = new byte[cipher.getOutputSize(inLen - encodedPublicKey.length)];
            len = cipher.processBytes(in_enc, inOff + encodedPublicKey.length, inLen - encodedPublicKey.length, M, 0);
            len += cipher.doFinal(M, len);
        }

        // Output the message.
        return Arrays.copyOfRange(M, 0, len);
    }


    public byte[] processBlock(
            byte[] in,
            int inOff,
            int inLen)
            throws InvalidCipherTextException
    {
        if (forEncryption)
        {
            if (keyPairGenerator != null)
            {
                EphemeralKeyPair ephKeyPair = keyPairGenerator.generate();

                this.privParam = ephKeyPair.getKeyPair().getPrivate();
                this.encodedPublicKey = ephKeyPair.getEncodedPublicKey();
            }
        }
        else
        {
            if (keyParser != null)
            {
                ByteArrayInputStream bIn = new ByteArrayInputStream(in, inOff, inLen);

                try
                {
                    this.pubParam = keyParser.readKey(bIn);
                }
                catch (IOException e)
                {
                    throw new InvalidCipherTextException("unable to recover ephemeral public key: " + e.getMessage(), e);
                }

                int encLength = (inLen - bIn.available());
                this.encodedPublicKey = Arrays.copyOfRange(in, inOff, inOff + encLength);
            }
        }

        // Compute the common value and convert to byte array.
        agree.init(privParam);
        BigInteger z = agree.calculateAgreement(pubParam);
        byte[] sharedSecret = BigIntegers.asUnsignedByteArray(agree.getFieldSize(), z);


        try
        {
            // Initialise the KDF.
            KDFParameters kdfParam = new KDFParameters(sharedSecret, encodedPublicKey);
            kdf.init(kdfParam);

            return forEncryption
                    ? encryptBlock(in, inOff, inLen)
                    : decryptBlock(in, inOff, inLen);
        }
        finally
        {
            Arrays.fill(sharedSecret, (byte)0);
        }
    }

}
