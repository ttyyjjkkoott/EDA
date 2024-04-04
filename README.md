# EDA
# Hybrid Encryption Decryption Algorithm

1. Generate a Symmetric Key: Dynamically generate a symmetric key for AES encryption. This key will encrypt the actual data.
2. Encrypt the Data: Use the symmetric key to encrypt the file. AES doesn't have the same size constraints as RSA, so it can handle larger files efficiently.
3. Encrypt the Symmetric Key: Use the RSA public key to encrypt the symmetric key. This way, only the holder of the RSA private key can decrypt it.
4. Combine Encrypted Data and Symmetric Key: The encrypted file will consist of the RSA-encrypted symmetric key followed by the AES-encrypted data.
5. Decryption Process: Reverse the process. Use the RSA private key to decrypt the symmetric key, and then use that to decrypt the data.