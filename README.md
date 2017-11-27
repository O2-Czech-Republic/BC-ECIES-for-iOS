# iOS-compatible ECIES implementation in Java

This is a porting of Bouncy Castle's IES engine to provide compatibility with Apple's `SecKeyCreateEncryptedData`, specifically the ECIES algortihms provided by Apple's internal Common Crypto and Core Crypto libraries when using one of the `SecKeyAlgorithmECIESEncryptionCofactorVariableIV*` algorithms (https://developer.apple.com/documentation/security/seckeyalgorithm).

Apple uses a rare implementation of ECIES which does not perform explicit message tagging, but instead uses an authenticated encryption (AEAD) variant of AES - AES-GCM. GCM (Galois/Counter mode) produces a message tag appended to the ciphertext similarly to other HMAC processes but allows for authentication data input.

## Cryptographic standards (based on iOS support)
#### Supported curves
- P-256 (secp256r1) only

#### Supported KDF
- ANSI X9.63 KDF using the following message digest algorithm:
  - SHA1
  - SHA224
  - SHA256
  - SHA384
  - SHA512
  
#### Supported symmetric encryption scheme
- AES (GCM) using:
  - 128-bit key (for EC keypairs <= 256 bits) - first part of the KDF output
  - 16-byte nonce - second part of the KDF output
  - 16 bytes long tag


## Encryption
This ECIES variant performs the following steps to produce ciphertext result:
1. A random ephemeral EC key pair is generated for each message
2. A Diffie-Hellman key exchange is performed over the **ephemeral private key and the peer (static) public key**. The result is a shared secret.
3. A KDF is used to expand the shared secret into 256 bits of shared information. Apple uses X9.63 KDF which is simply a SHA message digest of the concatenation of the shared secret, a 4-byte incremental counter, and the ephemeral **public** key data which serves as the initialization vector (IV).
4. The first half (128 bits) of the KDF result is used as the symmetric encryption key for AES-GCM, while the second half (128 bits) is used as the nonce. 
5. The output of the encryption process is a concatenation of (in this order):
   - the **ephemeral** public key
   - the output of the AES-GCM function (which itself is just a concatenation of the ciphertext and the message tag)


## Resources
##### Apple Open Source - Security Framework
https://opensource.apple.com/source/Security/Security-58286.1.32/keychain/SecKey.h.auto.html
See the description for `kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM` for example.
Please note that contrary to the description provided, Apple **does not** use authentication data in GCM.

##### Apple Open Source - Security Framework
https://opensource.apple.com/source/Security/Security-58286.1.32/OSX/shared_regressions/si-44-seckey-ies.m.auto.html
Test run for `kSecKeyAlgorithmECIESEncryptionCofactorX963SHA256AESGCM` provides useful debugging data.

##### Apple Core Crypto Source Code
https://github.com/samdmarshall/apple-corecrypto/blob/df1ffe4ae19dcb7c320d336d7f5f28c9af6daa09/ccecies/src/ccecies_encrypt_gcm_composite.c
`ccecies_encrypt_gcm_composite` provides ECIES implementation

##### Apple Core Crypto Testing Vectors
https://github.com/samdmarshall/apple-corecrypto/blob/df1ffe4ae19dcb7c320d336d7f5f28c9af6daa09/ccecies/test_vectors/ecies_aes_gcm.inc
