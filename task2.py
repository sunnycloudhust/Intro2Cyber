"""
Task 2 -- Reusing the pad. Uses only ciphertexts.txt produced by task1.py
(no access to the key).
"""
import string


def strxor(a: bytes, b: bytes) -> bytes:
    n = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(n))


def load_ciphertexts(path="ciphertexts.txt"):
    with open(path) as f:
        return [bytes.fromhex(line.strip()) for line in f if line.strip()]


def is_plausible(b: bytes) -> bool:
    allowed = (string.ascii_lowercase + " ").encode()
    return all(c in allowed for c in b)


def crib_drag(xor_ct: bytes, crib: bytes):
    """Slide `crib` along xor_ct; report positions where XOR-ing it in
    yields only lowercase letters and spaces."""
    hits = []
    crib_len = len(crib)
    for pos in range(len(xor_ct) - crib_len + 1):
        window = xor_ct[pos:pos + crib_len]
        guess = strxor(window, crib)
        if is_plausible(guess):
            hits.append((pos, guess.decode()))
    return hits


def main():
    cts = load_ciphertexts()
    c1, c2 = cts[0], cts[1]

    # c1 xor c2 == m1 xor m2 (key cancels out)
    xor12 = strxor(c1, c2)
    print("c1 xor c2 (hex):", xor12.hex())

    m1 = b"Send the final report to the dean before Friday noon."
    m2 = b"The exam for the course starts at eight in room D9."
    print("matches m1 xor m2:", xor12 == strxor(m1, m2))

    # crib dragging with " the "
    print("\ncrib dragging \" the \" over c1 xor c2:")
    for pos, guess in crib_drag(xor12, b" the "):
        print(f"  pos {pos:3d}: {guess!r}")

    # forge a key k' so that c1 decrypts to a chosen message
    target = b"Nothing to see here."
    target_padded = target + b" " * (len(c1) - len(target))
    k_prime = strxor(c1, target_padded)
    forged_pt = strxor(c1, k_prime)
    print("\nforged key k' (hex):", k_prime.hex())
    print("c1 decrypted under k':", forged_pt.decode())
    print("matches target:", forged_pt == target_padded)


if __name__ == "__main__":
    main()