# iOS-compatible ECIES implementation in Java

This is a porting of Bouncy Castle's IES engine to provide compatibility with Apple's `SecKeyCreateEncryptedData`, specifically the ECIES algortihms provided by Apple's internal Common Crypto and Core Crypto libraries.

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
2. A Diffie-Hellman key exchange is performed over the **ephemeral** private key and the **peer** public key. The result is a shared secret Z.
3. A KDF is used to expand the shared secret into 256 bits of shared information which is then split in half to produce symmetric key (first 128 bits) and nonce (last 128 bits). Apple uses X9.63 KDF which is simply a SHA message digest of the concatenation of the shared secret, a 4-byte incremental counter, and the ephemeral **public** key data which serves as the initialization vector (IV). The result is trimmed to the target key size (128 bits for EC curves <= 256 bits).
4. The result of the KDF is then used as the symmetric encryption key for AES-GCM, while an all-zero 16 bytes long byte array is used as the nonce.
5. The output of the encryption process is a concatenation of (in this order):
   - the **ephemeral** public key
   - the output of the AES-GCM function (which itself is just a concatenation of the ciphertext and the message tag)
