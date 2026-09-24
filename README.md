# Stream Cipher Key-Reuse Attack
The ciphertexts were provided in hexadecimal format and converted into byte arrays. Since the same keystream was reused, XORing two ciphertexts removes the key:

$$
C_i \oplus C_j = M_i \oplus M_j
$$

I first analyzed the XOR results at each byte position. When the XOR produced an ASCII letter frequently across multiple ciphertext pairs, I treated this as evidence that one of the corresponding plaintext characters was likely a space. Based on this assumption, candidate keystream bytes were recovered using:

$$
K_i = C_i \oplus 0x20
$$

The partially recovered keystream was then used to decrypt the ciphertexts and identify readable plaintext fragments.

For the final recovery, I used a guessed plaintext for the target ciphertext:

> `The secret message is: When using a stream cipher, never use the key more than once`

Given the guessed plaintext \(M\) and its ciphertext \(C\), the keystream can be recovered directly:

$$
K = C \oplus M
$$

The recovered keystream was then XORed with the other ciphertexts to cross-check the result. Finally, the recovered secret message was written to `secret.txt`.

This demonstrates the fundamental weakness of reusing a keystream: knowledge or partial recovery of one plaintext can expose the key stream and compromise other encrypted messages.
