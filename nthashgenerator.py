#!/usr/bin/env python3
"""NThashgenerator: compute NT hash (MD4 over UTF-16-LE) from a password.

Usage examples:
  nthashgenerator.py "myPassword123"
  echo -n "secret" | nthashgenerator.py -

Outputs the hex NT hash to stdout.

This file is intentionally dependency-free (pure Python) so it's convenient for CTFs.
"""

from __future__ import annotations
import argparse
import struct
import sys
from typing import Union


def _F(x, y, z):
    return ((x & y) | ((~x) & z)) & 0xFFFFFFFF


def _G(x, y, z):
    return ((x & y) | (x & z) | (y & z)) & 0xFFFFFFFF


def _H(x, y, z):
    return (x ^ y ^ z) & 0xFFFFFFFF


def _rol(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(message: Union[bytes, bytearray]) -> bytes:
    """Pure-Python MD4 implementation (public-domain style compact impl).

    Returns 16-byte digest.
    """
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476

    msg = bytearray(message)
    orig_len_bits = (8 * len(msg)) & 0xFFFFFFFFFFFFFFFF
    msg.append(0x80)
    while (len(msg) % 64) != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len_bits)

    for i in range(0, len(msg), 64):
        X = list(struct.unpack('<16I', msg[i:i+64]))
        AA, BB, CC, DD = A, B, C, D

        # Round 1
        s = [3, 7, 11, 19] * 4
        for j in range(16):
            k = j
            f = _F(B, C, D)
            A = _rol((A + f + X[k]) & 0xFFFFFFFF, s[j])
            A, B, C, D = D, A, B, C

        # Round 2
        s = [3, 5, 9, 13] * 4
        order = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for j in range(16):
            k = order[j]
            g = _G(B, C, D)
            A = _rol((A + g + X[k] + 0x5A827999) & 0xFFFFFFFF, s[j])
            A, B, C, D = D, A, B, C

        # Round 3
        s = [3, 9, 11, 15] * 4
        order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for j in range(16):
            k = order[j]
            h = _H(B, C, D)
            A = _rol((A + h + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s[j])
            A, B, C, D = D, A, B, C

        A = (A + AA) & 0xFFFFFFFF
        B = (B + BB) & 0xFFFFFFFF
        C = (C + CC) & 0xFFFFFFFF
        D = (D + DD) & 0xFFFFFFFF

    return struct.pack('<4I', A, B, C, D)


def ntlm_hash(password: str) -> str:
    """Return NT hash (hex) for a Unicode password string."""
    if not isinstance(password, str):
        raise TypeError("password must be a str")
    b = password.encode("utf-16-le")
    return md4(b).hex()


def main(argv=None):
    p = argparse.ArgumentParser(description="NThashgenerator — NT hash (MD4 over UTF-16LE)")
    p.add_argument("password", nargs="?", help='Password string, or "-" to read from stdin')
    p.add_argument("-q", "--quiet", action="store_true", help="Only print the hash")
    args = p.parse_args(argv)

    if args.password is None:
        p.print_help()
        return 1

    if args.password == "-":
        # read raw bytes from stdin, decode as utf-8 without newline by default
        raw = sys.stdin.buffer.read()
        try:
            passwd = raw.decode().rstrip("\n")
        except Exception:
            # fallback: interpret as latin-1
            passwd = raw.decode("latin-1").rstrip("\n")
    else:
        passwd = args.password

    h = ntlm_hash(passwd)

    if args.quiet:
        print(h)
    else:
        print(f"Password: {passwd}")
        print(f"NT hash: {h}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())