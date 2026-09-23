import os
class LFSR:
    def __init__(self, n, taps, seed):
        if seed == 0:
            raise ValueError("seed must not be 0 (the all-zero state is a "
                              "fixed point: it only ever outputs zeros)")
        self.n = n
        self.taps = taps
        self.row = seed & ((1 << n) - 1)

    def step(self):
        out = self.row & 1
        fb = 0
        for t in self.taps:
            fb ^= (self.row >> t) & 1
        self.row = (self.row >> 1) | (fb << (self.n - 1))
        return out

    def output_bits(self, k):
        return [self.step() for _ in range(k)]

    def output_bytes(self, nbytes):
        bits = self.output_bits(8 * nbytes)
        buf = bytearray(nbytes)
        for i, b in enumerate(bits):
            if b:
                buf[i // 8] |= (1 << (i % 8))
        return bytes(buf)


def period(n, taps, seed):
    lfsr = LFSR(n, taps, seed)
    start = lfsr.row
    steps = 0
    while True:
        lfsr.step()
        steps += 1
        if lfsr.row == start:
            return steps


def strxor(a, b):
    n = min(len(a), len(b))
    return bytes(a[i] ^ b[i] for i in range(n))


def part1():
    lfsr = LFSR(4, {0, 1}, 0b1001)
    bits = lfsr.output_bits(16)
    print("n=4, taps={0,1}, seed=1001 -> first 16 output bits:")
    print(" ".join(str(b) for b in bits))


def part2():
    configs = [
        (4, {0, 1}, 0b1001),
        (16, {0, 2, 3, 5}, 1),
        (16, {0, 8}, 1),
    ]
    print("\nperiod (steps to return to the seed):")
    for n, taps, seed in configs:
        p = period(n, taps, seed)
        max_p = (1 << n) - 1
        print(f"  n={n:2d} taps={sorted(taps)} seed={seed}: "
              f"period={p} (max possible = {max_p}, "
              f"{'maximal-length' if p == max_p else 'NOT maximal-length'})")


def part3():
    n, taps = 32, {0, 10, 30, 31}
    seed = int.from_bytes(os.urandom(4), "big") | 1  # avoid seed 0
    lfsr = LFSR(n, taps, seed)

    msg = ("From: exam-office@example.edu\n"
           "Subject: final exam\n"
           "Room B1-401, 8:00 on Monday.").encode()
    keystream = lfsr.output_bytes(len(msg))
    ct = strxor(keystream, msg)

    print(f"\nn=32, taps={sorted(taps)}")
    print("seed (hex):", f"{seed:08x}")
    print("ciphertext (hex):", ct.hex())

    # fraction of 1-bits in 64 KiB of output, from a fresh instance
    fresh = LFSR(n, taps, seed)
    out = fresh.output_bytes(64 * 1024)
    ones = sum(bin(byte).count("1") for byte in out)
    total_bits = len(out) * 8
    print(f"fraction of 1-bits in 64 KiB of output: "
          f"{ones}/{total_bits} = {ones/total_bits:.4f}")


if __name__ == "__main__":
    part1()
    part2()
    part3()