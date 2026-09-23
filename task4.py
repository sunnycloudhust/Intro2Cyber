import hashlib
import time
from pathlib import Path

from nacl.secret import SecretBox
from nacl.utils import random as random_bytes

CHUNK_SIZE = 1024 * 1024
PREFIX_SIZE = 16


def G(key: bytes, nonce: bytes, n: int) -> bytes:
    result = SecretBox(key).encrypt(bytes(n), nonce).ciphertext
    return result[SecretBox.MACBYTES:]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    value = int.from_bytes(a, "little") ^ int.from_bytes(b, "little")
    return value.to_bytes(len(a), "little")


def transform(source, destination, key: bytes, prefix: bytes, reuse_counter=False):
    i = 0
    while chunk := source.read(CHUNK_SIZE):
        counter = 0 if reuse_counter else i
        nonce = prefix + counter.to_bytes(8, "big")
        destination.write(xor_bytes(chunk, G(key, nonce, len(chunk))))
        i += 1


def encrypt_file(source: Path, destination: Path, key: bytes, prefix: bytes, reuse_counter=False):
    with source.open("rb") as src, destination.open("wb") as dst:
        dst.write(prefix)
        transform(src, dst, key, prefix, reuse_counter)


def decrypt_file(source: Path, destination: Path, key: bytes):
    with source.open("rb") as src, destination.open("wb") as dst:
        prefix = src.read(PREFIX_SIZE)
        transform(src, dst, key, prefix)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        while block := file.read(CHUNK_SIZE):
            digest.update(block)
    return digest.hexdigest()


def leaks_chunk_xor(book: Path, encrypted: Path) -> bool:
    with book.open("rb") as file:
        m0, m1 = file.read(CHUNK_SIZE), file.read(CHUNK_SIZE)
    with encrypted.open("rb") as file:
        file.read(PREFIX_SIZE)
        c0, c1 = file.read(CHUNK_SIZE), file.read(CHUNK_SIZE)
    return xor_bytes(c0, c1) == xor_bytes(m0, m1)


def main():
    folder = Path(__file__).resolve().parent
    book = folder / "book.pdf"
    encrypted = folder / "book.enc"
    decrypted = folder / "book.dec.pdf"
    buggy = folder / "book.bad.enc"
    key = random_bytes(SecretBox.KEY_SIZE)
    prefix = random_bytes(PREFIX_SIZE)

    start = time.perf_counter()
    encrypt_file(book, encrypted, key, prefix)
    elapsed = time.perf_counter() - start
    decrypt_file(encrypted, decrypted, key)
    encrypt_file(book, buggy, key, random_bytes(PREFIX_SIZE), True)

    with book.open("rb") as file:
        first_plaintext = file.read(16)
    with encrypted.open("rb") as file:
        stored_prefix = file.read(PREFIX_SIZE)
        first_ciphertext = file.read(16)

    book_hash = sha256(book)
    decrypted_hash = sha256(decrypted)
    print("Key:", key.hex())
    print("Prefix:", stored_prefix.hex())
    print("book.pdf size:", book.stat().st_size)
    print("book.enc size:", encrypted.stat().st_size)
    print("First 16 plaintext bytes:", first_plaintext.hex())
    print("First 16 ciphertext bytes:", first_ciphertext.hex())
    print("book.pdf SHA-256:", book_hash)
    print("book.dec.pdf SHA-256:", decrypted_hash)
    print("Hashes match:", book_hash == decrypted_hash)
    print("Encryption time:", f"{elapsed:.6f} seconds")
    print("Normal counters leak chunk XOR:", leaks_chunk_xor(book, encrypted))
    print("Forgotten counter leaks chunk XOR:", leaks_chunk_xor(book, buggy))


if __name__ == "__main__":
    main()
