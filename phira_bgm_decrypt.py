#!/usr/bin/env python3
# Phira "res/bgm" decryptor  (phira/src/inner.rs block cipher) + zstd
# usage: python phira_bgm_decrypt.py <input> <output.mp3>
import sys
try:
    import zstandard as zstd
except ImportError:
    from compression import zstd

def rol8(x, n): return ((x << n) | (x >> (8 - n))) & 0xFF

def dec_block(b):
    b[1], b[4] = b[4], b[1]
    b[2], b[6] = b[6], b[2]
    for i in range(8):
        t = rol8(i, 4)
        v17 = (((t & 0x33) << 2) | ((t >> 2) & 0x33)) & 0xFF
        v18 = ((((v17 & 0x50) << 1) | ((v17 >> 1) & 0x40)) & 0xFF) >> 5
        if i < v18:
            b[i], b[v18] = b[v18], b[i]
    b[1] = (b[1] - b[0]) & 0xFF
    b[3] = (b[3] - b[2]) & 0xFF
    b[5] = (b[5] - b[4]) & 0xFF
    b[7] = (b[7] - b[6]) & 0xFF
    b[2] = (b[2] - b[0]) & 0xFF
    b[3] = (b[3] - b[1]) & 0xFF
    b[6] = (b[6] - b[4]) & 0xFF
    b[7] = (b[7] - b[5]) & 0xFF
    b[4] = (b[4] - b[0]) & 0xFF
    b[5] = (b[5] - b[1]) & 0xFF
    b[6] = (b[6] - b[2]) & 0xFF
    b[7] = (b[7] - b[3]) & 0xFF
    b[3], b[5] = b[5], b[3]

def decrypt(data: bytes) -> bytes:
    d = bytearray(data)
    n = len(d)
    for o in range(0, n - n % 8, 8):   # full blocks only (file is 8-aligned)
        blk = d[o:o+8]
        dec_block(blk)
        d[o:o+8] = blk
    # trailing byte encodes padding: plain_len = len + last - 8
    k = n + d[n-1] - 8
    if n >= k:
        del d[k:]
    return bytes(d)

src, dst = sys.argv[1], sys.argv[2]
plain = decrypt(open(src, 'rb').read())
out = zstd.ZstdDecompressor().decompress(plain, max_output_size=512 << 20)
open(dst, 'wb').write(out)
print(f"OK: {len(out)} bytes -> {dst}")
