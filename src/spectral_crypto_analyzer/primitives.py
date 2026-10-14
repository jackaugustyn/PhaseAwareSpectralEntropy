"""Primitive catalog and 128-bit wrapper implementations.

This module is the abstraction layer between the analysis engine and concrete
cryptographic transformations. Every primitive is exposed via a common
``PrimitiveWrapper`` interface so the analyzer can treat block ciphers, stream
ciphers, hash projections, and reduced-round research variants uniformly.

High-level architecture:
- helper functions for byte/bit packing and projection to 128-bit state,
- wrapper classes implementing ``iterate(state, context)``,
- registry functions ``list_primitive_specs`` and ``build_primitive``.

Security note:
This code is intended for *analysis experiments*, not for production crypto.
Some wrappers intentionally alter standard constructions (e.g. reduced rounds,
projection/truncation, no feed-forward in compression studies).
"""

from __future__ import annotations

import hashlib
import importlib
import re
import struct
from dataclasses import dataclass

import numpy as np

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
except ImportError:  # pragma: no cover - optional runtime dependency
    Cipher = None  # type: ignore[assignment]
    algorithms = None  # type: ignore[assignment]
    modes = None  # type: ignore[assignment]

try:
    from Crypto.Cipher import Salsa20  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - optional runtime dependency
    Salsa20 = None  # type: ignore[assignment]

try:
    import blake3 as blake3_lib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - optional runtime dependency
    blake3_lib = None  # type: ignore[assignment]

BLOCK_BITS = 128
BLOCK_BYTES = BLOCK_BITS // 8


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings up to the shorter length."""
    return bytes(x ^ y for x, y in zip(a, b))


def normalize_name(name: str) -> str:
    """Normalise user-provided primitive names for lookup/aliases."""
    return name.strip().lower().replace("_", "-").replace(" ", "-")


def _pack_128(data: bytes) -> bytes:
    """Truncate or zero-pad payload to exactly 128 bits (16 bytes)."""
    return data[:BLOCK_BYTES].ljust(BLOCK_BYTES, b"\x00")


def _derive_key(master: bytes, size: int, domain: str) -> bytes:
    """Derive per-wrapper keys from one experiment key using domain separation."""
    return hashlib.blake2b(domain.encode("utf-8") + master, digest_size=size).digest()


def _project_first_128(data: bytes) -> bytes:
    return _pack_128(data)


def _project_xor_fold(data: bytes) -> bytes:
    folded = bytearray(BLOCK_BYTES)
    for idx, value in enumerate(data):
        folded[idx % BLOCK_BYTES] ^= value
    return bytes(folded)


def _project_selected_positions(data: bytes, positions: list[int]) -> bytes:
    if not positions:
        return _project_first_128(data)
    bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
    picked = np.array([bits[p % len(bits)] for p in positions[:BLOCK_BITS]], dtype=np.uint8)
    if len(picked) < BLOCK_BITS:
        padding = np.zeros(BLOCK_BITS - len(picked), dtype=np.uint8)
        picked = np.concatenate((picked, padding))
    return np.packbits(picked).tobytes()


def project_to_128(
    data: bytes, method: str = "first_128", selected_positions: list[int] | None = None
) -> bytes:
    normalized = normalize_name(method)
    if normalized in {"first-128", "first128"}:
        return _project_first_128(data)
    if normalized in {"xor-fold", "xor_fold", "fold"}:
        return _project_xor_fold(data)
    if normalized in {"selected-positions", "selected_positions"}:
        return _project_selected_positions(data, selected_positions or [])
    raise ValueError("Unsupported projection method. Use first_128, xor_fold, selected_positions.")


@dataclass(slots=True)
class PrimitiveSpec:
    name: str
    family: str
    implementation: str
    notes: str


@dataclass(slots=True)
class PrimitiveContext:
    key: bytes
    projection_method: str
    selected_positions: list[int]


class PrimitiveWrapper:
    """Abstract wrapper contract consumed by the analyzer."""
    spec: PrimitiveSpec

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        raise NotImplementedError

    def wrapper_description(self) -> dict[str, str]:
        raise NotImplementedError


@dataclass(slots=True)
class RealBlockCipherWrapper(PrimitiveWrapper):
    spec: PrimitiveSpec
    algorithm_name: str
    key_size: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        # Stateless deterministic mapping: pack state to block size, derive a
        # wrapper-specific key, then encrypt one block in ECB mode.
        block = _pack_128(state)
        key = _derive_key(context.key, self.key_size, f"block:{self.algorithm_name}")
        return self._encrypt_block(block, key)

    def _encrypt_block(self, block: bytes, key: bytes) -> bytes:
        if self.algorithm_name in {"AES", "Camellia", "ARIA", "SM4"}:
            return self._cryptography_encrypt(self.algorithm_name, key, block)
        if self.algorithm_name in {"Serpent", "Twofish"}:
            return self._pycryptodome_encrypt(self.algorithm_name, key, block)
        raise RuntimeError(f"Unsupported block algorithm backend for {self.spec.name}.")

    def _cryptography_encrypt(self, algo_name: str, key: bytes, block: bytes) -> bytes:
        if Cipher is None or algorithms is None or modes is None:
            raise RuntimeError(f"{self.spec.name} requires 'cryptography'.")
        if algo_name == "AES":
            algo = algorithms.AES(key)
        elif algo_name == "Camellia":
            algo = algorithms.Camellia(key)
        elif algo_name == "ARIA":
            if not hasattr(algorithms, "ARIA"):
                raise RuntimeError("ARIA is not available in your cryptography/OpenSSL build.")
            algo = algorithms.ARIA(key)  # type: ignore[attr-defined]
        else:
            if not hasattr(algorithms, "SM4"):
                raise RuntimeError("SM4 is not available in your cryptography/OpenSSL build.")
            algo = algorithms.SM4(key)  # type: ignore[attr-defined]

        cipher = Cipher(algo, modes.ECB())
        encryptor = cipher.encryptor()
        return encryptor.update(block) + encryptor.finalize()

    def _pycryptodome_encrypt(self, module_name: str, key: bytes, block: bytes) -> bytes:
        try:
            module = importlib.import_module(f"Crypto.Cipher.{module_name}")
        except ImportError as exc:
            raise RuntimeError(
                f"{self.spec.name} requires backend support for {module_name} in pycryptodome."
            ) from exc
        cipher = module.new(key, module.MODE_ECB)
        return cipher.encrypt(block)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "block-cipher",
            "formula": "y[i+1] = E_K(y[i])",
            "algorithm": self.spec.name,
            "packing": "state packed/truncated to 128 bits",
        }


@dataclass(slots=True)
class RealStreamWrapper(PrimitiveWrapper):
    spec: PrimitiveSpec
    algorithm_name: str

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        # For stream ciphers we reinterpret current state as nonce/counter seed
        # and take the first 128 bits of generated keystream.
        packed = _pack_128(state)
        if self.algorithm_name == "ChaCha20":
            return self._chacha20(packed, context)
        if self.algorithm_name == "Salsa20":
            return self._salsa20(packed, context)
        raise RuntimeError(f"{self.spec.name} is optional and not integrated in this build.")

    def _chacha20(self, state: bytes, context: PrimitiveContext) -> bytes:
        if Cipher is None or algorithms is None:
            raise RuntimeError("ChaCha20 wrapper requires 'cryptography'.")
        key = _derive_key(context.key, 32, "stream:chacha20")
        nonce = state[:16]
        cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
        encryptor = cipher.encryptor()
        return encryptor.update(b"\x00" * 64)[:BLOCK_BYTES]

    def _salsa20(self, state: bytes, context: PrimitiveContext) -> bytes:
        if Salsa20 is None:
            raise RuntimeError("Salsa20 wrapper requires 'pycryptodome'.")
        key = _derive_key(context.key, 32, "stream:salsa20")
        nonce = state[:8]
        cipher = Salsa20.new(key=key, nonce=nonce)
        return cipher.encrypt(b"\x00" * 64)[:BLOCK_BYTES]

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "stream-wrapper",
            "formula": "y[i+1] = KS(K, y[i])[0:128]",
            "algorithm": self.spec.name,
            "packing": "y[i] interpreted as nonce/counter seed",
        }


@dataclass(slots=True)
class HashWrapper(PrimitiveWrapper):
    spec: PrimitiveSpec
    algorithm: str

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        # Hash output can be wider than 128 bits, therefore a projection step
        # is explicit and configurable in the experiment context.
        digest = self._digest(_pack_128(state))
        return project_to_128(
            digest,
            method=context.projection_method,
            selected_positions=context.selected_positions,
        )

    def _digest(self, payload: bytes) -> bytes:
        if self.algorithm == "md5":
            return hashlib.md5(payload).digest()
        if self.algorithm == "sha1":
            return hashlib.sha1(payload).digest()
        if self.algorithm == "sha256":
            return hashlib.sha256(payload).digest()
        if self.algorithm == "sha3_256":
            return hashlib.sha3_256(payload).digest()
        if self.algorithm == "blake2s":
            return hashlib.blake2s(payload).digest()
        if self.algorithm == "blake2b":
            return hashlib.blake2b(payload).digest()
        if blake3_lib is None:
            raise RuntimeError("BLAKE3 wrapper requires 'blake3' package.")
        return blake3_lib.blake3(payload).digest()

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "hash-projection",
            "formula": "y[i+1] = P(H(y[i]))",
            "algorithm": self.spec.name,
            "projection": self.spec.notes,
        }


@dataclass(slots=True)
class IdealRandomBaselineWrapper(PrimitiveWrapper):
    spec: PrimitiveSpec

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        # Pseudo-random control mapping keyed by experiment key; used as a
        # baseline for "near-random" expectations in metrics.
        block = _pack_128(state)
        return hashlib.blake2s(b"blake2s-128-reference" + context.key + block, digest_size=16).digest()

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "control-baseline",
            "formula": "y[i+1] = F_K(y[i]) pseudo-random control mapping",
            "algorithm": self.spec.name,
        }


# ---------------------------------------------------------------------------
# Reduced-round MD5 compression (pure Python, configurable round count)
# and other reduced-round primitives
# ---------------------------------------------------------------------------

_MD5_K = [
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
]

_MD5_S = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
]

_MD5_G = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    1, 6, 11, 0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12,
    5, 8, 11, 14, 1, 4, 7, 10, 13, 0, 3, 6, 9, 12, 15, 2,
    0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9,
]

_MD5_IV = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476)

_MASK32 = 0xFFFFFFFF


def _md5_rotl(x: int, n: int) -> int:
    """32-bit left rotation."""
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _md5_compress_reduced(data: bytes, num_rounds: int) -> bytes:
    """MD5 compression with *num_rounds* of 64 internal rounds.

    Input 128 bits are placed in message words M[0..3]; M[4..15] = 0.
    The standard IV is used.  No Davies-Meyer feed-forward is applied so
    the output directly reflects the round chain's mixing quality.
    """
    msg = data[:BLOCK_BYTES].ljust(64, b"\x00")
    m_words = struct.unpack("<16I", msg)

    a, b, c, d = _MD5_IV

    for i in range(min(num_rounds, 64)):
        if i < 16:
            f = (b & c) | ((~b & _MASK32) & d)
        elif i < 32:
            f = (b & d) | (c & ((~d) & _MASK32))
        elif i < 48:
            f = b ^ c ^ d
        else:
            f = c ^ (b | ((~d) & _MASK32))

        f &= _MASK32
        g = _MD5_G[i]
        tmp = (a + f + _MD5_K[i] + m_words[g]) & _MASK32
        tmp = _md5_rotl(tmp, _MD5_S[i])
        tmp = (b + tmp) & _MASK32

        a, b, c, d = d, tmp, b, c

    return struct.pack("<4I", a & _MASK32, b & _MASK32, c & _MASK32, d & _MASK32)


@dataclass(slots=True)
class ReducedRoundMD5Wrapper(PrimitiveWrapper):
    """Wrapper for reduced-round MD5 compression (1-64 rounds)."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        return _md5_compress_reduced(_pack_128(state), self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-md5",
            "formula": f"y[i+1] = MD5_compress(y[i], rounds={self.num_rounds})",
            "algorithm": self.spec.name,
            "notes": (
                f"{self.num_rounds} of 64 internal rounds, "
                "standard IV, no Davies-Meyer feed-forward"
            ),
        }
# NOTE FOR MAINTAINERS:
# The blocks below re-declare reduced-round SHA/AES helpers that are already
# defined earlier in this file. Python keeps the last definition, so runtime
# behaviour comes from this later copy. This is functional but risky for code
# review, debugging, and future edits because changes in one copy may silently
# be shadowed by the other.
#
# Recommended cleanup: keep one canonical implementation block and remove the
# duplicate declarations.
# ---------------------------------------------------------------------------
# Reduced-round SHA-1 and SHA-256 compression
# ---------------------------------------------------------------------------

_SHA1_IV = (
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
)


def _sha1_rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _sha1_compress_reduced(data: bytes, num_rounds: int) -> bytes:
    """SHA-1 compression with *num_rounds* of 80 internal rounds.

    Input 128 bits are placed in M[0..3] (big-endian); M[4..15] = 0.
    Standard IV, no feed-forward.
    """
    msg = data[:BLOCK_BYTES].ljust(64, b"\x00")
    w = list(struct.unpack(">16I", msg))
    for t in range(16, 80):
        val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]
        w.append(_sha1_rotl(val, 1))

    a, b, c, d, e = _SHA1_IV
    rounds = min(num_rounds, 80)
    for t in range(rounds):
        if t < 20:
            f = (b & c) | ((~b & _MASK32) & d)
            k = 0x5A827999
        elif t < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        temp = (_sha1_rotl(a, 5) + f + e + k + w[t]) & _MASK32
        e = d
        d = c
        c = _sha1_rotl(b, 30)
        b = a
        a = temp

    return struct.pack(">5I", a & _MASK32, b & _MASK32, c & _MASK32, d & _MASK32, e & _MASK32)


_SHA256_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

_SHA256_K = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]


def _sha256_rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _sha256_shr(x: int, n: int) -> int:
    return (x >> n) & _MASK32


def _sha256_sigma0(x: int) -> int:
    return _sha256_rotr(x, 7) ^ _sha256_rotr(x, 18) ^ _sha256_shr(x, 3)


def _sha256_sigma1(x: int) -> int:
    return _sha256_rotr(x, 17) ^ _sha256_rotr(x, 19) ^ _sha256_shr(x, 10)


def _sha256_capsig0(x: int) -> int:
    return _sha256_rotr(x, 2) ^ _sha256_rotr(x, 13) ^ _sha256_rotr(x, 22)


def _sha256_capsig1(x: int) -> int:
    return _sha256_rotr(x, 6) ^ _sha256_rotr(x, 11) ^ _sha256_rotr(x, 25)


def _sha256_compress_reduced(data: bytes, num_rounds: int) -> bytes:
    """SHA-256 compression with *num_rounds* of 64 internal rounds.

    Input 128 bits are placed in the first 16 bytes of the block; the rest
    is zero.  Standard IV, no feed-forward.
    """
    msg = data[:BLOCK_BYTES].ljust(64, b"\x00")
    w = list(struct.unpack(">16I", msg))
    for t in range(16, 64):
        val = (
            _sha256_sigma1(w[t - 2])
            + w[t - 7]
            + _sha256_sigma0(w[t - 15])
            + w[t - 16]
        ) & _MASK32
        w.append(val)

    a, b, c, d, e, f, g, h = _SHA256_IV
    rounds = min(num_rounds, 64)
    for t in range(rounds):
        ch = (e & f) ^ ((~e & _MASK32) & g)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t1 = (h + _sha256_capsig1(e) + ch + _SHA256_K[t] + w[t]) & _MASK32
        t2 = (_sha256_capsig0(a) + maj) & _MASK32
        h = g
        g = f
        f = e
        e = (d + t1) & _MASK32
        d = c
        c = b
        b = a
        a = (t1 + t2) & _MASK32

    return struct.pack(">8I", a, b, c, d, e, f, g, h)


@dataclass(slots=True)
class ReducedRoundSHA1Wrapper(PrimitiveWrapper):
    """Wrapper for reduced-round SHA-1 compression (1-80 rounds)."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        raw = _sha1_compress_reduced(_pack_128(state), self.num_rounds)
        return project_to_128(
            raw,
            method=context.projection_method,
            selected_positions=context.selected_positions,
        )

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-sha1",
            "formula": f"y[i+1] = SHA1_compress(y[i], rounds={self.num_rounds})",
            "algorithm": self.spec.name,
            "notes": (
                f"{self.num_rounds} of 80 internal rounds, "
                "standard IV, no feed-forward; output projected to 128 bits"
            ),
        }


@dataclass(slots=True)
class ReducedRoundSHA256Wrapper(PrimitiveWrapper):
    """Wrapper for reduced-round SHA-256 compression (1-64 rounds)."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        raw = _sha256_compress_reduced(_pack_128(state), self.num_rounds)
        return project_to_128(
            raw,
            method=context.projection_method,
            selected_positions=context.selected_positions,
        )

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-sha256",
            "formula": f"y[i+1] = SHA256_compress(y[i], rounds={self.num_rounds})",
            "algorithm": self.spec.name,
            "notes": (
                f"{self.num_rounds} of 64 internal rounds, "
                "standard IV, no feed-forward"
            ),
        }


# ---------------------------------------------------------------------------
# Reduced-round AES-128 (pure Python, configurable round count)
# ---------------------------------------------------------------------------

_AES_SBOX = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0,
    0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
    0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A,
    0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0,
    0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B,
    0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85,
    0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
    0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17,
    0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88,
    0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C,
    0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9,
    0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
    0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E,
    0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94,
    0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68,
    0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
]

_AES_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]


def _aes_sub_word(w: int) -> int:
    return (
        (_AES_SBOX[(w >> 24) & 0xFF] << 24)
        | (_AES_SBOX[(w >> 16) & 0xFF] << 16)
        | (_AES_SBOX[(w >> 8) & 0xFF] << 8)
        | _AES_SBOX[w & 0xFF]
    )


def _aes_rot_word(w: int) -> int:
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


def _aes_key_schedule_128(key: bytes) -> list[bytes]:
    """Return list of round keys (11 x 16 bytes) for AES-128."""
    if len(key) != 16:
        raise ValueError("AES-128 key must be 16 bytes")
    w = list(struct.unpack(">4I", key))
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = _aes_sub_word(_aes_rot_word(temp)) ^ (_AES_RCON[(i // 4) - 1] << 24)
        w.append(w[i - 4] ^ temp)
    round_keys: list[bytes] = []
    for r in range(11):
        words = w[4 * r : 4 * (r + 1)]
        round_keys.append(struct.pack(">4I", *words))
    return round_keys


def _aes_sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = _AES_SBOX[state[i]]


def _aes_shift_rows(state: list[int]) -> None:
    # state is in column-major: index = row + 4 * col
    def idx(r: int, c: int) -> int:
        return r + 4 * c

    new = state.copy()
    for r in range(4):
        shift = r
        for c in range(4):
            new[idx(r, c)] = state[idx(r, (c + shift) % 4)]
    state[:] = new


def _aes_xtime(x: int) -> int:
    return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else (x << 1) & 0xFF


def _aes_mix_single_column(col: list[int]) -> list[int]:
    a0, a1, a2, a3 = col
    t = a0 ^ a1 ^ a2 ^ a3
    r0 = a0 ^ t ^ _aes_xtime(a0 ^ a1)
    r1 = a1 ^ t ^ _aes_xtime(a1 ^ a2)
    r2 = a2 ^ t ^ _aes_xtime(a2 ^ a3)
    r3 = a3 ^ t ^ _aes_xtime(a3 ^ a0)
    return [r0 & 0xFF, r1 & 0xFF, r2 & 0xFF, r3 & 0xFF]


def _aes_mix_columns(state: list[int]) -> None:
    for c in range(4):
        col = [state[r + 4 * c] for r in range(4)]
        mixed = _aes_mix_single_column(col)
        for r in range(4):
            state[r + 4 * c] = mixed[r]


def _aes_add_round_key(state: list[int], round_key: bytes) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


def _aes_encrypt_block_128_reduced(block: bytes, key: bytes, rounds: int) -> bytes:
    """AES-128 encryption with configurable number of rounds (1–10).

    Performs the standard initial AddRoundKey, then *rounds* iterations of:
    SubBytes, ShiftRows, (MixColumns if not last), AddRoundKey.
    """
    if not 1 <= rounds <= 10:
        raise ValueError(f"AES-128 round count must be 1-10, got {rounds}")
    round_keys = _aes_key_schedule_128(key)
    state = list(block)
    _aes_add_round_key(state, round_keys[0])
    for r in range(1, rounds + 1):
        _aes_sub_bytes(state)
        _aes_shift_rows(state)
        if r != rounds:
            _aes_mix_columns(state)
        _aes_add_round_key(state, round_keys[r])
    return bytes(state)


@dataclass(slots=True)
class ReducedRoundAES128Wrapper(PrimitiveWrapper):
    """Wrapper for reduced-round AES-128 (1–10 rounds)."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        block = _pack_128(state)
        key = _derive_key(context.key, 16, "block:AES-128-RR")
        return _aes_encrypt_block_128_reduced(block, key, self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-aes-128",
            "formula": f"y[i+1] = AES128_R^{self.num_rounds}(y[i])",
            "algorithm": self.spec.name,
            "notes": f"{self.num_rounds} of 10 AES-128 rounds, ECB mode",
        }



# ---------------------------------------------------------------------------
# Reduced-round SHA-1 and SHA-256 compression
# ---------------------------------------------------------------------------

_SHA1_IV = (
    0x67452301,
    0xEFCDAB89,
    0x98BADCFE,
    0x10325476,
    0xC3D2E1F0,
)


def _sha1_rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & _MASK32


def _sha1_compress_reduced(data: bytes, num_rounds: int) -> bytes:
    """SHA-1 compression with *num_rounds* of 80 internal rounds.

    Input 128 bits are placed in M[0..3] (big-endian); M[4..15] = 0.
    Standard IV, no feed-forward.
    """
    msg = data[:BLOCK_BYTES].ljust(64, b"\x00")
    w = list(struct.unpack(">16I", msg))
    for t in range(16, 80):
        val = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]
        w.append(_sha1_rotl(val, 1))

    a, b, c, d, e = _SHA1_IV
    rounds = min(num_rounds, 80)
    for t in range(rounds):
        if t < 20:
            f = (b & c) | ((~b & _MASK32) & d)
            k = 0x5A827999
        elif t < 40:
            f = b ^ c ^ d
            k = 0x6ED9EBA1
        elif t < 60:
            f = (b & c) | (b & d) | (c & d)
            k = 0x8F1BBCDC
        else:
            f = b ^ c ^ d
            k = 0xCA62C1D6
        temp = (_sha1_rotl(a, 5) + f + e + k + w[t]) & _MASK32
        e = d
        d = c
        c = _sha1_rotl(b, 30)
        b = a
        a = temp

    return struct.pack(">5I", a & _MASK32, b & _MASK32, c & _MASK32, d & _MASK32, e & _MASK32)


_SHA256_IV = (
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
)

_SHA256_K = [
    0x428A2F98,
    0x71374491,
    0xB5C0FBCF,
    0xE9B5DBA5,
    0x3956C25B,
    0x59F111F1,
    0x923F82A4,
    0xAB1C5ED5,
    0xD807AA98,
    0x12835B01,
    0x243185BE,
    0x550C7DC3,
    0x72BE5D74,
    0x80DEB1FE,
    0x9BDC06A7,
    0xC19BF174,
    0xE49B69C1,
    0xEFBE4786,
    0x0FC19DC6,
    0x240CA1CC,
    0x2DE92C6F,
    0x4A7484AA,
    0x5CB0A9DC,
    0x76F988DA,
    0x983E5152,
    0xA831C66D,
    0xB00327C8,
    0xBF597FC7,
    0xC6E00BF3,
    0xD5A79147,
    0x06CA6351,
    0x14292967,
    0x27B70A85,
    0x2E1B2138,
    0x4D2C6DFC,
    0x53380D13,
    0x650A7354,
    0x766A0ABB,
    0x81C2C92E,
    0x92722C85,
    0xA2BFE8A1,
    0xA81A664B,
    0xC24B8B70,
    0xC76C51A3,
    0xD192E819,
    0xD6990624,
    0xF40E3585,
    0x106AA070,
    0x19A4C116,
    0x1E376C08,
    0x2748774C,
    0x34B0BCB5,
    0x391C0CB3,
    0x4ED8AA4A,
    0x5B9CCA4F,
    0x682E6FF3,
    0x748F82EE,
    0x78A5636F,
    0x84C87814,
    0x8CC70208,
    0x90BEFFFA,
    0xA4506CEB,
    0xBEF9A3F7,
    0xC67178F2,
]


def _sha256_rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & _MASK32


def _sha256_shr(x: int, n: int) -> int:
    return (x >> n) & _MASK32


def _sha256_sigma0(x: int) -> int:
    return _sha256_rotr(x, 7) ^ _sha256_rotr(x, 18) ^ _sha256_shr(x, 3)


def _sha256_sigma1(x: int) -> int:
    return _sha256_rotr(x, 17) ^ _sha256_rotr(x, 19) ^ _sha256_shr(x, 10)


def _sha256_capsig0(x: int) -> int:
    return _sha256_rotr(x, 2) ^ _sha256_rotr(x, 13) ^ _sha256_rotr(x, 22)


def _sha256_capsig1(x: int) -> int:
    return _sha256_rotr(x, 6) ^ _sha256_rotr(x, 11) ^ _sha256_rotr(x, 25)


def _sha256_compress_reduced(data: bytes, num_rounds: int) -> bytes:
    """SHA-256 compression with *num_rounds* of 64 internal rounds.

    Input 128 bits are placed in the first 16 bytes of the block; the rest
    is zero.  Standard IV, no feed-forward.
    """
    msg = data[:BLOCK_BYTES].ljust(64, b"\x00")
    w = list(struct.unpack(">16I", msg))
    for t in range(16, 64):
        val = (
            _sha256_sigma1(w[t - 2])
            + w[t - 7]
            + _sha256_sigma0(w[t - 15])
            + w[t - 16]
        ) & _MASK32
        w.append(val)

    a, b, c, d, e, f, g, h = _SHA256_IV
    rounds = min(num_rounds, 64)
    for t in range(rounds):
        ch = (e & f) ^ ((~e & _MASK32) & g)
        maj = (a & b) ^ (a & c) ^ (b & c)
        t1 = (h + _sha256_capsig1(e) + ch + _SHA256_K[t] + w[t]) & _MASK32
        t2 = (_sha256_capsig0(a) + maj) & _MASK32
        h = g
        g = f
        f = e
        e = (d + t1) & _MASK32
        d = c
        c = b
        b = a
        a = (t1 + t2) & _MASK32

    return struct.pack(">8I", a, b, c, d, e, f, g, h)


@dataclass(slots=True)
class ReducedRoundSHA1Wrapper(PrimitiveWrapper):
    """Wrapper for reduced-round SHA-1 compression (1–80 rounds)."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        raw = _sha1_compress_reduced(_pack_128(state), self.num_rounds)
        return project_to_128(
            raw,
            method=context.projection_method,
            selected_positions=context.selected_positions,
        )

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-sha1",
            "formula": f"y[i+1] = SHA1_compress(y[i], rounds={self.num_rounds})",
            "algorithm": self.spec.name,
            "notes": (
                f"{self.num_rounds} of 80 internal rounds, "
                "standard IV, no feed-forward; output projected to 128 bits"
            ),
        }


@dataclass(slots=True)
class ReducedRoundSHA256Wrapper(PrimitiveWrapper):
    """Wrapper for reduced-round SHA-256 compression (1–64 rounds)."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        raw = _sha256_compress_reduced(_pack_128(state), self.num_rounds)
        return project_to_128(
            raw,
            method=context.projection_method,
            selected_positions=context.selected_positions,
        )

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-sha256",
            "formula": f"y[i+1] = SHA256_compress(y[i], rounds={self.num_rounds})",
            "algorithm": self.spec.name,
            "notes": (
                f"{self.num_rounds} of 64 internal rounds, "
                "standard IV, no feed-forward"
            ),
        }


# ---------------------------------------------------------------------------
# Reduced-round AES-128 (pure Python, configurable round count)
# ---------------------------------------------------------------------------

_AES_SBOX = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]

_AES_RCON = [
    0x01,
    0x02,
    0x04,
    0x08,
    0x10,
    0x20,
    0x40,
    0x80,
    0x1B,
    0x36,
]


def _aes_sub_word(w: int) -> int:
    return (
        (_AES_SBOX[(w >> 24) & 0xFF] << 24)
        | (_AES_SBOX[(w >> 16) & 0xFF] << 16)
        | (_AES_SBOX[(w >> 8) & 0xFF] << 8)
        | _AES_SBOX[w & 0xFF]
    )


def _aes_rot_word(w: int) -> int:
    return ((w << 8) | (w >> 24)) & 0xFFFFFFFF


def _aes_key_schedule_128(key: bytes) -> list[bytes]:
    """Return list of round keys (11 x 16 bytes) for AES-128."""
    assert len(key) == 16
    w = list(struct.unpack(">4I", key))
    for i in range(4, 44):
        temp = w[i - 1]
        if i % 4 == 0:
            temp = _aes_sub_word(_aes_rot_word(temp)) ^ (_AES_RCON[(i // 4) - 1] << 24)
        w.append(w[i - 4] ^ temp)
    round_keys: list[bytes] = []
    for r in range(11):
        words = w[4 * r : 4 * (r + 1)]
        round_keys.append(struct.pack(">4I", *words))
    return round_keys


def _aes_sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = _AES_SBOX[state[i]]


def _aes_shift_rows(state: list[int]) -> None:
    # state is in column-major: index = row + 4 * col
    def idx(r: int, c: int) -> int:
        return r + 4 * c

    new = state.copy()
    for r in range(4):
        shift = r
        for c in range(4):
            new[idx(r, c)] = state[idx(r, (c + shift) % 4)]
    state[:] = new


def _aes_xtime(x: int) -> int:
    return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else (x << 1) & 0xFF


def _aes_mix_single_column(col: list[int]) -> list[int]:
    a0, a1, a2, a3 = col
    t = a0 ^ a1 ^ a2 ^ a3
    r0 = a0 ^ t ^ _aes_xtime(a0 ^ a1)
    r1 = a1 ^ t ^ _aes_xtime(a1 ^ a2)
    r2 = a2 ^ t ^ _aes_xtime(a2 ^ a3)
    r3 = a3 ^ t ^ _aes_xtime(a3 ^ a0)
    return [r0 & 0xFF, r1 & 0xFF, r2 & 0xFF, r3 & 0xFF]


def _aes_mix_columns(state: list[int]) -> None:
    for c in range(4):
        col = [state[r + 4 * c] for r in range(4)]
        mixed = _aes_mix_single_column(col)
        for r in range(4):
            state[r + 4 * c] = mixed[r]


def _aes_add_round_key(state: list[int], round_key: bytes) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


def _aes_encrypt_block_128_reduced(block: bytes, key: bytes, rounds: int) -> bytes:
    """AES-128 encryption with configurable number of rounds (1–10).

    Performs the standard initial AddRoundKey, then *rounds* iterations of:
    SubBytes, ShiftRows, (MixColumns if not last), AddRoundKey.
    """
    if not 1 <= rounds <= 10:
        raise ValueError(f"AES-128 round count must be 1-10, got {rounds}")
    round_keys = _aes_key_schedule_128(key)
    state = list(block)
    _aes_add_round_key(state, round_keys[0])
    for r in range(1, rounds + 1):
        _aes_sub_bytes(state)
        _aes_shift_rows(state)
        if r != rounds:
            _aes_mix_columns(state)
        _aes_add_round_key(state, round_keys[r])
    return bytes(state)


@dataclass(slots=True)
class ReducedRoundAES128Wrapper(PrimitiveWrapper):
    """Wrapper for reduced-round AES-128 (1–10 rounds)."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        block = _pack_128(state)
        key = _derive_key(context.key, 16, "block:AES-128-RR")
        return _aes_encrypt_block_128_reduced(block, key, self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-aes-128",
            "formula": f"y[i+1] = AES128_R^{self.num_rounds}(y[i])",
            "algorithm": self.spec.name,
            "notes": f"{self.num_rounds} of 10 AES-128 rounds, ECB mode",
        }


def _bytes_to_bits_msb(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def _bytes_to_bits_lsb(data: bytes) -> list[int]:
    """Expand bytes in the bit order used by bit-oriented stream ciphers."""
    return [(byte >> shift) & 1 for byte in data for shift in range(8)]


def _bits_to_bytes_msb(bits: list[int]) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (7 - (i % 8))
    return bytes(out)


def _bits_to_bytes_lsb(bits: list[int]) -> bytes:
    """Pack the first generated bit into the least-significant byte position."""
    out = bytearray((len(bits) + 7) // 8)
    for i, bit in enumerate(bits):
        if bit:
            out[i // 8] |= 1 << (i % 8)
    return bytes(out)


def _trivium_keystream_128(
    key80: bytes, iv80: bytes, warmup_rounds: int, output_bits: int = BLOCK_BITS
) -> bytes:
    """Return keystream bits from Trivium after warm-up clocks (128 by default)."""
    if len(key80) != 10 or len(iv80) != 10:
        raise ValueError("Trivium requires 80-bit key and 80-bit IV.")
    # The eSTREAM byte convention loads and emits bits least-significant first.
    k = _bytes_to_bits_lsb(key80)
    iv = _bytes_to_bits_lsb(iv80)

    a = k + ([0] * 13)  # 93 bits
    b = iv + ([0] * 4)  # 84 bits
    c = ([0] * 108) + [1, 1, 1]  # 111 bits

    for _ in range(max(0, warmup_rounds)):
        t1 = a[65] ^ a[92]
        t2 = b[68] ^ b[83]
        t3 = c[65] ^ c[110]
        t1 ^= (a[90] & a[91]) ^ b[77]
        t2 ^= (b[81] & b[82]) ^ c[86]
        t3 ^= (c[108] & c[109]) ^ a[68]
        a = [t3] + a[:-1]
        b = [t1] + b[:-1]
        c = [t2] + c[:-1]

    out_bits: list[int] = []
    for _ in range(output_bits):
        t1 = a[65] ^ a[92]
        t2 = b[68] ^ b[83]
        t3 = c[65] ^ c[110]
        z = t1 ^ t2 ^ t3
        out_bits.append(z)
        t1 ^= (a[90] & a[91]) ^ b[77]
        t2 ^= (b[81] & b[82]) ^ c[86]
        t3 ^= (c[108] & c[109]) ^ a[68]
        a = [t3] + a[:-1]
        b = [t1] + b[:-1]
        c = [t2] + c[:-1]

    return _bits_to_bytes_lsb(out_bits)


def _grain128_keystream_128(
    key128: bytes, iv96: bytes, warmup_rounds: int, output_bits: int = BLOCK_BITS
) -> bytes:
    """Return keystream bits from the original eSTREAM Grain-128 core (128 by default)."""
    if len(key128) != 16 or len(iv96) != 12:
        raise ValueError("Grain-128 requires 128-bit key and 96-bit IV.")
    b = _bytes_to_bits_lsb(key128)  # NFSR (128 bits)
    s = _bytes_to_bits_lsb(iv96) + ([1] * 32)  # LFSR (128 bits)

    def h_func(nfsr: list[int], lfsr: list[int]) -> int:
        return (
            (nfsr[12] & lfsr[8])
            ^ (lfsr[13] & lfsr[20])
            ^ (nfsr[95] & lfsr[42])
            ^ (lfsr[60] & lfsr[79])
            ^ (nfsr[12] & nfsr[95] & lfsr[95])
        )

    def z_func(nfsr: list[int], lfsr: list[int]) -> int:
        return (
            h_func(nfsr, lfsr)
            ^ lfsr[93]
            ^ nfsr[2]
            ^ nfsr[15]
            ^ nfsr[36]
            ^ nfsr[45]
            ^ nfsr[64]
            ^ nfsr[73]
            ^ nfsr[89]
        )

    def nfsr_feedback(nfsr: list[int], lfsr: list[int]) -> int:
        return (
            lfsr[0]
            ^ nfsr[0]
            ^ nfsr[26]
            ^ nfsr[56]
            ^ nfsr[91]
            ^ nfsr[96]
            ^ (nfsr[3] & nfsr[67])
            ^ (nfsr[11] & nfsr[13])
            ^ (nfsr[17] & nfsr[18])
            ^ (nfsr[27] & nfsr[59])
            ^ (nfsr[40] & nfsr[48])
            ^ (nfsr[61] & nfsr[65])
            ^ (nfsr[68] & nfsr[84])
        )

    def lfsr_feedback(lfsr: list[int]) -> int:
        return lfsr[0] ^ lfsr[7] ^ lfsr[38] ^ lfsr[70] ^ lfsr[81] ^ lfsr[96]

    for _ in range(max(0, warmup_rounds)):
        z = z_func(b, s)
        b_new = nfsr_feedback(b, s) ^ z
        s_new = lfsr_feedback(s) ^ z
        b = b[1:] + [b_new]
        s = s[1:] + [s_new]

    out_bits: list[int] = []
    for _ in range(output_bits):
        z = z_func(b, s)
        out_bits.append(z)
        b_new = nfsr_feedback(b, s)
        s_new = lfsr_feedback(s)
        b = b[1:] + [b_new]
        s = s[1:] + [s_new]

    return _bits_to_bytes_lsb(out_bits)


@dataclass(slots=True)
class ReducedRoundTriviumWrapper(PrimitiveWrapper):
    """Wrapper for reduced-round Trivium warm-up clocks."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        key = _derive_key(context.key, 10, "stream:trivium-rr-key")
        iv = _pack_128(state)[:10]
        return _trivium_keystream_128(key, iv, self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-trivium",
            "formula": f"y[i+1] = Trivium(y[i], warmup={self.num_rounds})[0:128]",
            "algorithm": self.spec.name,
            "notes": f"{self.num_rounds} warm-up clocks, then first 128 keystream bits",
        }


@dataclass(slots=True)
class ReducedRoundGrainWrapper(PrimitiveWrapper):
    """Wrapper for reduced-round Grain-128 warm-up clocks."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        key = _derive_key(context.key, 16, "stream:grain-rr-key")
        iv = _pack_128(state)[:12]
        return _grain128_keystream_128(key, iv, self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-grain-128",
            "formula": f"y[i+1] = Grain128(y[i], warmup={self.num_rounds})[0:128]",
            "algorithm": self.spec.name,
            "notes": f"{self.num_rounds} warm-up clocks, then first 128 keystream bits",
        }


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _le_words_to_bytes(words: list[int]) -> bytes:
    return b"".join(struct.pack("<I", word & 0xFFFFFFFF) for word in words)


def _rc4_keystream_128(key: bytes, drop_rounds: int) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    for _ in range(max(0, drop_rounds)):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        _ = s[(s[i] + s[j]) & 0xFF]

    out = bytearray()
    while len(out) < BLOCK_BYTES:
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out.append(s[(s[i] + s[j]) & 0xFF])
    return bytes(out)


def _a5_1_keystream_128(key64: bytes, frame22: int, warmup_rounds: int) -> bytes:
    if len(key64) != 8:
        raise ValueError("A5/1 requires a 64-bit key.")

    masks = (0x07FFFF, 0x3FFFFF, 0x7FFFFF)
    taps = (0x072000, 0x300000, 0x700080)
    mids = (0x000100, 0x000400, 0x000400)
    outputs = (0x040000, 0x200000, 0x400000)
    registers = [0, 0, 0]

    def parity(value: int) -> int:
        return value.bit_count() & 1

    def clock_one(index: int) -> None:
        registers[index] = (
            ((registers[index] << 1) & masks[index])
            | parity(registers[index] & taps[index])
        )

    # The published reference implementation loads the least-significant bit
    # of the first key byte first, then the frame number least-significant bit.
    for bit in _bytes_to_bits_lsb(key64):
        for j in range(3):
            clock_one(j)
            registers[j] ^= bit
    for i in range(22):
        bit = (frame22 >> i) & 1
        for j in range(3):
            clock_one(j)
            registers[j] ^= bit

    def majority_clock() -> None:
        control = [1 if registers[j] & mids[j] else 0 for j in range(3)]
        majority = (control[0] & control[1]) | (control[0] & control[2]) | (
            control[1] & control[2]
        )
        for j in range(3):
            if control[j] == majority:
                clock_one(j)

    for _ in range(max(0, warmup_rounds)):
        majority_clock()

    out_bits: list[int] = []
    for _ in range(BLOCK_BITS):
        majority_clock()
        out_bits.append(
            (1 if registers[0] & outputs[0] else 0)
            ^ (1 if registers[1] & outputs[1] else 0)
            ^ (1 if registers[2] & outputs[2] else 0)
        )
    return _bits_to_bytes_msb(out_bits)


def _chacha20_block_reduced(key32: bytes, nonce12: bytes, counter: int, rounds: int) -> bytes:
    if len(key32) != 32 or len(nonce12) != 12:
        raise ValueError("ChaCha20 core requires 256-bit key and 96-bit nonce.")
    if not (2 <= rounds <= 20 and rounds % 2 == 0):
        raise ValueError(f"ChaCha20 reduced rounds must be even and in 2..20, got {rounds}")

    def qr(state: list[int], a: int, b: int, c: int, d: int) -> None:
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = _rotl32(state[d], 16)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = _rotl32(state[b], 12)
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = _rotl32(state[d], 8)
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = _rotl32(state[b], 7)

    constants = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    key_words = list(struct.unpack("<8I", key32))
    nonce_words = list(struct.unpack("<3I", nonce12))
    state = constants + key_words + [counter & 0xFFFFFFFF] + nonce_words
    working = state.copy()

    for _ in range(rounds // 2):
        qr(working, 0, 4, 8, 12)
        qr(working, 1, 5, 9, 13)
        qr(working, 2, 6, 10, 14)
        qr(working, 3, 7, 11, 15)
        qr(working, 0, 5, 10, 15)
        qr(working, 1, 6, 11, 12)
        qr(working, 2, 7, 8, 13)
        qr(working, 3, 4, 9, 14)

    out_words = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return _le_words_to_bytes(out_words)


def _salsa20_block_reduced(key32: bytes, nonce8: bytes, counter: int, rounds: int) -> bytes:
    if len(key32) != 32 or len(nonce8) != 8:
        raise ValueError("Salsa20 core requires 256-bit key and 64-bit nonce.")
    if not (2 <= rounds <= 20 and rounds % 2 == 0):
        raise ValueError(f"Salsa20 reduced rounds must be even and in 2..20, got {rounds}")

    k = list(struct.unpack("<8I", key32))
    n0, n1 = struct.unpack("<2I", nonce8)
    c0 = counter & 0xFFFFFFFF
    c1 = (counter >> 32) & 0xFFFFFFFF
    sigma = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]

    state = [
        sigma[0], k[0], k[1], k[2],
        k[3], sigma[1], n0, n1,
        c0, c1, sigma[2], k[4],
        k[5], k[6], k[7], sigma[3],
    ]
    x = state.copy()

    for _ in range(rounds // 2):
        x[4] ^= _rotl32((x[0] + x[12]) & 0xFFFFFFFF, 7)
        x[8] ^= _rotl32((x[4] + x[0]) & 0xFFFFFFFF, 9)
        x[12] ^= _rotl32((x[8] + x[4]) & 0xFFFFFFFF, 13)
        x[0] ^= _rotl32((x[12] + x[8]) & 0xFFFFFFFF, 18)
        x[9] ^= _rotl32((x[5] + x[1]) & 0xFFFFFFFF, 7)
        x[13] ^= _rotl32((x[9] + x[5]) & 0xFFFFFFFF, 9)
        x[1] ^= _rotl32((x[13] + x[9]) & 0xFFFFFFFF, 13)
        x[5] ^= _rotl32((x[1] + x[13]) & 0xFFFFFFFF, 18)
        x[14] ^= _rotl32((x[10] + x[6]) & 0xFFFFFFFF, 7)
        x[2] ^= _rotl32((x[14] + x[10]) & 0xFFFFFFFF, 9)
        x[6] ^= _rotl32((x[2] + x[14]) & 0xFFFFFFFF, 13)
        x[10] ^= _rotl32((x[6] + x[2]) & 0xFFFFFFFF, 18)
        x[3] ^= _rotl32((x[15] + x[11]) & 0xFFFFFFFF, 7)
        x[7] ^= _rotl32((x[3] + x[15]) & 0xFFFFFFFF, 9)
        x[11] ^= _rotl32((x[7] + x[3]) & 0xFFFFFFFF, 13)
        x[15] ^= _rotl32((x[11] + x[7]) & 0xFFFFFFFF, 18)
        x[1] ^= _rotl32((x[0] + x[3]) & 0xFFFFFFFF, 7)
        x[2] ^= _rotl32((x[1] + x[0]) & 0xFFFFFFFF, 9)
        x[3] ^= _rotl32((x[2] + x[1]) & 0xFFFFFFFF, 13)
        x[0] ^= _rotl32((x[3] + x[2]) & 0xFFFFFFFF, 18)
        x[6] ^= _rotl32((x[5] + x[4]) & 0xFFFFFFFF, 7)
        x[7] ^= _rotl32((x[6] + x[5]) & 0xFFFFFFFF, 9)
        x[4] ^= _rotl32((x[7] + x[6]) & 0xFFFFFFFF, 13)
        x[5] ^= _rotl32((x[4] + x[7]) & 0xFFFFFFFF, 18)
        x[11] ^= _rotl32((x[10] + x[9]) & 0xFFFFFFFF, 7)
        x[8] ^= _rotl32((x[11] + x[10]) & 0xFFFFFFFF, 9)
        x[9] ^= _rotl32((x[8] + x[11]) & 0xFFFFFFFF, 13)
        x[10] ^= _rotl32((x[9] + x[8]) & 0xFFFFFFFF, 18)
        x[12] ^= _rotl32((x[15] + x[14]) & 0xFFFFFFFF, 7)
        x[13] ^= _rotl32((x[12] + x[15]) & 0xFFFFFFFF, 9)
        x[14] ^= _rotl32((x[13] + x[12]) & 0xFFFFFFFF, 13)
        x[15] ^= _rotl32((x[14] + x[13]) & 0xFFFFFFFF, 18)

    out = [(x[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return _le_words_to_bytes(out)


@dataclass(slots=True)
class RC4Wrapper(PrimitiveWrapper):
    spec: PrimitiveSpec

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        key = _derive_key(context.key, 16, "stream:rc4")
        drop = int.from_bytes(_pack_128(state)[:2], "big") + 1
        return _rc4_keystream_128(key, drop)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "stream-wrapper-rc4",
            "formula": "y[i+1] = RC4(K, drop=f(y[i]))[0:128]",
            "algorithm": self.spec.name,
            "packing": "y[i] modulates PRGA drop count",
        }


@dataclass(slots=True)
class A51Wrapper(PrimitiveWrapper):
    spec: PrimitiveSpec

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        key = _derive_key(context.key, 8, "stream:a5-1")
        frame = int.from_bytes(_pack_128(state)[:4], "big") & ((1 << 22) - 1)
        return _a5_1_keystream_128(key, frame, warmup_rounds=100)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "stream-wrapper-a5-1",
            "formula": "y[i+1] = A5/1(K, frame=f(y[i]))[0:128]",
            "algorithm": self.spec.name,
            "packing": "y[i] provides 22-bit frame number",
        }


@dataclass(slots=True)
class ReducedRoundRC4Wrapper(PrimitiveWrapper):
    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        packed = _pack_128(state)
        base_key = _derive_key(context.key, 16, "stream:rc4-rr")
        # Make reduced-round RC4 stateful while keeping runtime bounded:
        # - state-dependent key tweak (domain-separated 16-byte digest),
        # - small state-dependent offset added to nominal drop rounds.
        tweak = hashlib.blake2b(b"rc4-rr-state" + packed, digest_size=16).digest()
        key = xor_bytes(base_key, tweak)
        offset = int.from_bytes(packed[:2], "big") % 257  # 0..256
        drop = self.num_rounds + offset
        return _rc4_keystream_128(key, drop)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-rc4",
            "formula": (
                f"y[i+1] = RC4(K xor h(y[i]), "
                f"drop={self.num_rounds}+g(y[i]))[0:128]"
            ),
            "algorithm": self.spec.name,
            "notes": (
                f"{self.num_rounds} nominal PRGA warm-up steps + "
                f"state-dependent offset in [0,256] and state-dependent key tweak"
            ),
        }


@dataclass(slots=True)
class DirectKeyRC4Wrapper(PrimitiveWrapper):
    """RC4 control without hash pre-diffusion or state-dependent drop offset."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        base_key = _derive_key(context.key, 16, "stream:rc4-direct")
        key = xor_bytes(base_key, _pack_128(state))
        return _rc4_keystream_128(key, self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "direct-key-rc4",
            "formula": (
                f"y[i+1] = RC4(K xor y[i], drop={self.num_rounds})[0:128]"
            ),
            "algorithm": self.spec.name,
            "notes": "16-byte direct XOR key map; fixed nominal drop; no hash pre-diffusion",
        }


@dataclass(slots=True)
class ReducedRoundA51Wrapper(PrimitiveWrapper):
    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        key = _derive_key(context.key, 8, "stream:a5-1-rr")
        frame = int.from_bytes(_pack_128(state)[:4], "big") & ((1 << 22) - 1)
        return _a5_1_keystream_128(key, frame, warmup_rounds=self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-a5-1",
            "formula": f"y[i+1] = A5/1(y[i], warmup={self.num_rounds})[0:128]",
            "algorithm": self.spec.name,
            "notes": f"{self.num_rounds} majority-clock warm-up cycles, then 128 bits",
        }


@dataclass(slots=True)
class ReducedRoundChaCha20Wrapper(PrimitiveWrapper):
    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        key = _derive_key(context.key, 32, "stream:chacha20-rr")
        packed = _pack_128(state)
        nonce = packed[:12]
        counter = int.from_bytes(packed[12:16], "little")
        return _chacha20_block_reduced(key, nonce, counter, self.num_rounds)[:BLOCK_BYTES]

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-chacha20",
            "formula": f"y[i+1] = ChaCha20_block(y[i], rounds={self.num_rounds})[0:128]",
            "algorithm": self.spec.name,
            "notes": f"{self.num_rounds} rounds of ChaCha20 core (even, 2..20)",
        }


@dataclass(slots=True)
class ReducedRoundSalsa20Wrapper(PrimitiveWrapper):
    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        key = _derive_key(context.key, 32, "stream:salsa20-rr")
        packed = _pack_128(state)
        nonce = packed[:8]
        counter = int.from_bytes(packed[8:16], "little")
        return _salsa20_block_reduced(key, nonce, counter, self.num_rounds)[:BLOCK_BYTES]

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-salsa20",
            "formula": f"y[i+1] = Salsa20_block(y[i], rounds={self.num_rounds})[0:128]",
            "algorithm": self.spec.name,
            "notes": f"{self.num_rounds} rounds of Salsa20 core (even, 2..20)",
        }


# ---------------------------------------------------------------------------
# Additional reduced-round block ciphers (DES, SM4, Speck128, PRESENT)
# ---------------------------------------------------------------------------

from .block_reduced import (  # noqa: E402
    _DES_ROUNDS,
    _PRESENT_ROUNDS,
    _SM4_ROUNDS,
    _SPECK128_ROUNDS,
    des_encrypt_reduced,
    present80_encrypt_reduced,
    sm4_encrypt_reduced,
    speck128_encrypt_reduced,
)


@dataclass(slots=True)
class ReducedRoundDESWrapper(PrimitiveWrapper):
    """DES with configurable Feistel rounds; two 64-bit halves in parallel ECB."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        block = _pack_128(state)
        key = _derive_key(context.key, 8, "block:DES-RR")
        return des_encrypt_reduced(block, key, self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-des",
            "formula": f"y[i+1] = DES_R^{self.num_rounds}(y_L) || DES_R^{self.num_rounds}(y_R)",
            "algorithm": self.spec.name,
            "notes": (
                f"{self.num_rounds} of {_DES_ROUNDS} DES Feistel rounds; "
                "128-bit state as two parallel 64-bit blocks"
            ),
        }


@dataclass(slots=True)
class ReducedRoundSM4Wrapper(PrimitiveWrapper):
    """SM4 with configurable number of Feistel rounds (1–32)."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        block = _pack_128(state)
        key = _derive_key(context.key, 16, "block:SM4-RR")
        return sm4_encrypt_reduced(block, key, self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-sm4",
            "formula": f"y[i+1] = SM4_R^{self.num_rounds}(y[i])",
            "algorithm": self.spec.name,
            "notes": f"{self.num_rounds} of {_SM4_ROUNDS} SM4 Feistel rounds, ECB",
        }


@dataclass(slots=True)
class ReducedRoundSpeck128Wrapper(PrimitiveWrapper):
    """Speck128/128 with configurable ARX rounds (1–32)."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        block = _pack_128(state)
        key = _derive_key(context.key, 16, "block:Speck128-RR")
        return speck128_encrypt_reduced(block, key, self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-speck128",
            "formula": f"y[i+1] = Speck128_R^{self.num_rounds}(y[i])",
            "algorithm": self.spec.name,
            "notes": f"{self.num_rounds} of {_SPECK128_ROUNDS} Speck128/128 ARX rounds, ECB",
        }


@dataclass(slots=True)
class ReducedRoundPRESENTWrapper(PrimitiveWrapper):
    """PRESENT-80 with configurable SPN rounds; two 64-bit halves in parallel ECB."""

    spec: PrimitiveSpec
    num_rounds: int

    def iterate(self, state: bytes, context: PrimitiveContext) -> bytes:
        block = _pack_128(state)
        key = _derive_key(context.key, 10, "block:PRESENT-RR")
        return present80_encrypt_reduced(block, key, self.num_rounds)

    def wrapper_description(self) -> dict[str, str]:
        return {
            "wrapper": "reduced-round-present",
            "formula": (
                f"y[i+1] = PRESENT_R^{self.num_rounds}(y_L) || "
                f"PRESENT_R^{self.num_rounds}(y_R)"
            ),
            "algorithm": self.spec.name,
            "notes": (
                f"{self.num_rounds} of {_PRESENT_ROUNDS} PRESENT-80 rounds; "
                "128-bit state as two parallel 64-bit blocks"
            ),
        }


def list_primitive_specs() -> list[PrimitiveSpec]:
    """Return human-readable catalog used by CLI/help/report outputs."""
    return [
        PrimitiveSpec("AES-128", "block", "cryptography", "real AES-128 ECB encryption per iteration"),
        PrimitiveSpec("AES-256", "block", "cryptography", "real AES-256 ECB encryption per iteration"),
        PrimitiveSpec("Camellia-128", "block", "cryptography", "real Camellia-128 ECB encryption per iteration"),
        PrimitiveSpec("Camellia-256", "block", "cryptography", "real Camellia-256 ECB encryption per iteration"),
        PrimitiveSpec("Serpent", "block", "pycryptodome-if-available", "real Serpent ECB if backend provides cipher"),
        PrimitiveSpec("Twofish", "block", "pycryptodome-if-available", "real Twofish ECB if backend provides cipher"),
        PrimitiveSpec("ARIA", "block", "cryptography-if-available", "real ARIA ECB if backend provides cipher"),
        PrimitiveSpec("SM4", "block", "cryptography-if-available", "real SM4 ECB if backend provides cipher"),
        PrimitiveSpec("DES", "block", "custom", "DES dual-ECB full 16 Feistel rounds (128-bit state)"),
        PrimitiveSpec("Speck128", "block", "custom", "Speck128/128 ECB full 32 ARX rounds"),
        PrimitiveSpec("PRESENT", "block", "custom", "PRESENT-80 dual-ECB full 31 SPN rounds (128-bit state)"),
        PrimitiveSpec("ChaCha20", "stream", "cryptography", "real ChaCha20 keystream, first 128 bits"),
        PrimitiveSpec("Salsa20", "stream", "pycryptodome", "real Salsa20 keystream, first 128 bits"),
        PrimitiveSpec("RC4", "stream", "custom", "RC4 keystream with state-dependent drop"),
        PrimitiveSpec("A5/1", "stream", "custom", "A5/1 keystream with state-derived frame number"),
        PrimitiveSpec("ZUC", "stream", "not-integrated", "optional, backend not bundled"),
        PrimitiveSpec("SNOW 3G", "stream", "not-integrated", "optional, backend not bundled"),
        PrimitiveSpec("MD5", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
        PrimitiveSpec("SHA-1", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
        PrimitiveSpec("SHA-256", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
        PrimitiveSpec("SHA-3-256", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
        PrimitiveSpec("BLAKE2s", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
        PrimitiveSpec("BLAKE2b", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
        PrimitiveSpec("BLAKE3", "hash", "blake3", "projection: first_128/xor_fold/selected_positions"),
        PrimitiveSpec("Ideal-Random-128", "block", "control-baseline", "pseudo-random baseline mapping"),
        PrimitiveSpec("MD5-NR", "hash", "custom", "reduced-round MD5 compression (1-64), e.g. MD5-16R"),
        PrimitiveSpec("SHA-1-NR", "hash", "custom", "reduced-round SHA-1 compression (1-80), e.g. SHA-1-32R"),
        PrimitiveSpec("SHA-256-NR", "hash", "custom", "reduced-round SHA-256 compression (1-64), e.g. SHA-256-32R"),
        PrimitiveSpec("AES-128-NR", "block", "custom", "reduced-round AES-128 (1-10), e.g. AES-128-4R"),
        PrimitiveSpec("DES-NR", "block", "custom", "reduced-round DES (1-16), dual 64-bit ECB, e.g. DES-8R"),
        PrimitiveSpec("SM4-NR", "block", "custom", "reduced-round SM4 (1-32), e.g. SM4-16R"),
        PrimitiveSpec("Speck128-NR", "block", "custom", "reduced-round Speck128/128 (1-32), e.g. Speck128-16R"),
        PrimitiveSpec("PRESENT-NR", "block", "custom", "reduced-round PRESENT-80 (1-31), dual 64-bit ECB, e.g. PRESENT-16R"),
        PrimitiveSpec("Trivium-NR", "stream", "custom", "reduced-round Trivium warm-up clocks, e.g. Trivium-288R"),
        PrimitiveSpec("Grain-NR", "stream", "custom", "reduced-round Grain-128 warm-up clocks, e.g. Grain-256R"),
        PrimitiveSpec("RC4-NR", "stream", "custom", "reduced-round RC4 drop count, e.g. RC4-256R"),
        PrimitiveSpec("A5/1-NR", "stream", "custom", "reduced-round A5/1 warm-up clocks, e.g. A5-1-100R"),
        PrimitiveSpec("ChaCha20-NR", "stream", "custom", "reduced-round ChaCha20 core, e.g. ChaCha20-8R"),
        PrimitiveSpec("Salsa20-NR", "stream", "custom", "reduced-round Salsa20 core, e.g. Salsa20-8R"),
    ]


def build_primitive(name: str) -> PrimitiveWrapper:
    """Resolve a primitive name/alias into a concrete wrapper instance.

    Resolution strategy:
    1. exact lookup in static alias table (real primitives + baseline),
    2. regex-based parsing for reduced-round variants (e.g. ``md5-16r``),
    3. raise ValueError with full catalog for user guidance.
    """
    normalized = normalize_name(name)
    table: dict[str, PrimitiveWrapper] = {
        "aes-128": RealBlockCipherWrapper(
            PrimitiveSpec("AES-128", "block", "cryptography", "real AES-128 ECB encryption per iteration"),
            algorithm_name="AES",
            key_size=16,
        ),
        "aes-256": RealBlockCipherWrapper(
            PrimitiveSpec("AES-256", "block", "cryptography", "real AES-256 ECB encryption per iteration"),
            algorithm_name="AES",
            key_size=32,
        ),
        "camellia-128": RealBlockCipherWrapper(
            PrimitiveSpec("Camellia-128", "block", "cryptography", "real Camellia-128 ECB encryption per iteration"),
            algorithm_name="Camellia",
            key_size=16,
        ),
        "camellia-256": RealBlockCipherWrapper(
            PrimitiveSpec("Camellia-256", "block", "cryptography", "real Camellia-256 ECB encryption per iteration"),
            algorithm_name="Camellia",
            key_size=32,
        ),
        "serpent": RealBlockCipherWrapper(
            PrimitiveSpec("Serpent", "block", "pycryptodome-if-available", "real Serpent ECB if backend provides cipher"),
            algorithm_name="Serpent",
            key_size=32,
        ),
        "twofish": RealBlockCipherWrapper(
            PrimitiveSpec("Twofish", "block", "pycryptodome-if-available", "real Twofish ECB if backend provides cipher"),
            algorithm_name="Twofish",
            key_size=32,
        ),
        "aria": RealBlockCipherWrapper(
            PrimitiveSpec("ARIA", "block", "cryptography-if-available", "real ARIA ECB if backend provides cipher"),
            algorithm_name="ARIA",
            key_size=16,
        ),
        "sm4": RealBlockCipherWrapper(
            PrimitiveSpec("SM4", "block", "cryptography-if-available", "real SM4 ECB if backend provides cipher"),
            algorithm_name="SM4",
            key_size=16,
        ),
        "des": ReducedRoundDESWrapper(
            PrimitiveSpec("DES", "block", "custom", "DES dual-ECB full 16 Feistel rounds"),
            num_rounds=_DES_ROUNDS,
        ),
        "speck128": ReducedRoundSpeck128Wrapper(
            PrimitiveSpec("Speck128", "block", "custom", "Speck128/128 ECB full 32 ARX rounds"),
            num_rounds=_SPECK128_ROUNDS,
        ),
        "present": ReducedRoundPRESENTWrapper(
            PrimitiveSpec("PRESENT", "block", "custom", "PRESENT-80 dual-ECB full 31 SPN rounds"),
            num_rounds=_PRESENT_ROUNDS,
        ),
        "chacha20": RealStreamWrapper(
            PrimitiveSpec("ChaCha20", "stream", "cryptography", "real ChaCha20 keystream, first 128 bits"),
            algorithm_name="ChaCha20",
        ),
        "salsa20": RealStreamWrapper(
            PrimitiveSpec("Salsa20", "stream", "pycryptodome", "real Salsa20 keystream, first 128 bits"),
            algorithm_name="Salsa20",
        ),
        "rc4": RC4Wrapper(
            PrimitiveSpec("RC4", "stream", "custom", "RC4 keystream with state-dependent drop")
        ),
        "a5/1": A51Wrapper(
            PrimitiveSpec("A5/1", "stream", "custom", "A5/1 keystream with state-derived frame number")
        ),
        "a5-1": A51Wrapper(
            PrimitiveSpec("A5/1", "stream", "custom", "A5/1 keystream with state-derived frame number")
        ),
        "zuc": RealStreamWrapper(
            PrimitiveSpec("ZUC", "stream", "not-integrated", "optional, backend not bundled"),
            algorithm_name="ZUC",
        ),
        "snow-3g": RealStreamWrapper(
            PrimitiveSpec("SNOW 3G", "stream", "not-integrated", "optional, backend not bundled"),
            algorithm_name="SNOW3G",
        ),
        "md5": HashWrapper(
            PrimitiveSpec("MD5", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
            algorithm="md5",
        ),
        "md-5": HashWrapper(
            PrimitiveSpec("MD5", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
            algorithm="md5",
        ),
        "sha-1": HashWrapper(
            PrimitiveSpec("SHA-1", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
            algorithm="sha1",
        ),
        "sha1": HashWrapper(
            PrimitiveSpec("SHA-1", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
            algorithm="sha1",
        ),
        "sha-256": HashWrapper(
            PrimitiveSpec("SHA-256", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
            algorithm="sha256",
        ),
        "sha256": HashWrapper(
            PrimitiveSpec("SHA-256", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
            algorithm="sha256",
        ),
        "sha-3-256": HashWrapper(
            PrimitiveSpec("SHA-3-256", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
            algorithm="sha3_256",
        ),
        "blake2s": HashWrapper(
            PrimitiveSpec("BLAKE2s", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
            algorithm="blake2s",
        ),
        "blake2b": HashWrapper(
            PrimitiveSpec("BLAKE2b", "hash", "hashlib", "projection: first_128/xor_fold/selected_positions"),
            algorithm="blake2b",
        ),
        "blake3": HashWrapper(
            PrimitiveSpec("BLAKE3", "hash", "blake3", "projection: first_128/xor_fold/selected_positions"),
            algorithm="blake3",
        ),
        "ideal-random-128": IdealRandomBaselineWrapper(
            PrimitiveSpec("Ideal-Random-128", "block", "control-baseline", "pseudo-random baseline mapping")
        ),
    }
    if normalized in table:
        return table[normalized]

    # Reduced-round MD5: matches patterns like md5-16r, md5-4r, etc.
    md5_rr = re.match(r"^md5-(\d+)r$", normalized)
    if md5_rr:
        nr = int(md5_rr.group(1))
        if not 1 <= nr <= 64:
            raise ValueError(f"MD5 round count must be 1-64, got {nr}")
        return ReducedRoundMD5Wrapper(
            spec=PrimitiveSpec(
                f"MD5-{nr}R",
                "hash",
                "custom",
                f"MD5 compression, {nr}/64 rounds, no feed-forward",
            ),
            num_rounds=nr,
        )

    # Reduced-round SHA-1: sha-1-32r or sha1-32r
    sha1_rr = re.match(r"^sha-?1-(\d+)r$", normalized)
    if sha1_rr:
        nr = int(sha1_rr.group(1))
        if not 1 <= nr <= 80:
            raise ValueError(f"SHA-1 round count must be 1-80, got {nr}")
        return ReducedRoundSHA1Wrapper(
            spec=PrimitiveSpec(
                f"SHA-1-{nr}R",
                "hash",
                "custom",
                f"SHA-1 compression, {nr}/80 rounds, no feed-forward",
            ),
            num_rounds=nr,
        )

    # Reduced-round SHA-256: sha-256-32r or sha256-32r
    sha256_rr = re.match(r"^sha-?256-(\d+)r$", normalized)
    if sha256_rr:
        nr = int(sha256_rr.group(1))
        if not 1 <= nr <= 64:
            raise ValueError(f"SHA-256 round count must be 1-64, got {nr}")
        return ReducedRoundSHA256Wrapper(
            spec=PrimitiveSpec(
                f"SHA-256-{nr}R",
                "hash",
                "custom",
                f"SHA-256 compression, {nr}/64 rounds, no feed-forward",
            ),
            num_rounds=nr,
        )

    # Reduced-round AES-128: aes-128-4r etc.
    aes_rr = re.match(r"^aes-128-(\d+)r$", normalized)
    if aes_rr:
        nr = int(aes_rr.group(1))
        if not 1 <= nr <= 10:
            raise ValueError(f"AES-128 round count must be 1-10, got {nr}")
        return ReducedRoundAES128Wrapper(
            spec=PrimitiveSpec(
                f"AES-128-{nr}R",
                "block",
                "custom",
                f"AES-128 ECB, {nr}/10 rounds (reduced-round)",
            ),
            num_rounds=nr,
        )

    # Reduced-round DES: des-8r etc. (dual 64-bit ECB → 128-bit state)
    des_rr = re.match(r"^des-(\d+)r$", normalized)
    if des_rr:
        nr = int(des_rr.group(1))
        if not 1 <= nr <= _DES_ROUNDS:
            raise ValueError(f"DES round count must be 1-{_DES_ROUNDS}, got {nr}")
        return ReducedRoundDESWrapper(
            spec=PrimitiveSpec(
                f"DES-{nr}R",
                "block",
                "custom",
                f"DES dual-ECB, {nr}/{_DES_ROUNDS} Feistel rounds",
            ),
            num_rounds=nr,
        )

    # Reduced-round SM4: sm4-16r etc.
    sm4_rr = re.match(r"^sm4-(\d+)r$", normalized)
    if sm4_rr:
        nr = int(sm4_rr.group(1))
        if not 1 <= nr <= _SM4_ROUNDS:
            raise ValueError(f"SM4 round count must be 1-{_SM4_ROUNDS}, got {nr}")
        return ReducedRoundSM4Wrapper(
            spec=PrimitiveSpec(
                f"SM4-{nr}R",
                "block",
                "custom",
                f"SM4 ECB, {nr}/{_SM4_ROUNDS} Feistel rounds",
            ),
            num_rounds=nr,
        )

    # Reduced-round Speck128/128: speck128-16r, speck-128-16r
    speck_rr = re.match(r"^speck(?:-?128)?-(\d+)r$", normalized)
    if speck_rr:
        nr = int(speck_rr.group(1))
        if not 1 <= nr <= _SPECK128_ROUNDS:
            raise ValueError(f"Speck128 round count must be 1-{_SPECK128_ROUNDS}, got {nr}")
        return ReducedRoundSpeck128Wrapper(
            spec=PrimitiveSpec(
                f"Speck128-{nr}R",
                "block",
                "custom",
                f"Speck128/128 ECB, {nr}/{_SPECK128_ROUNDS} ARX rounds",
            ),
            num_rounds=nr,
        )

    # Reduced-round PRESENT-80: present-16r, present-80-16r
    present_rr = re.match(r"^present(?:-?80)?-(\d+)r$", normalized)
    if present_rr:
        nr = int(present_rr.group(1))
        if not 1 <= nr <= _PRESENT_ROUNDS:
            raise ValueError(f"PRESENT round count must be 1-{_PRESENT_ROUNDS}, got {nr}")
        return ReducedRoundPRESENTWrapper(
            spec=PrimitiveSpec(
                f"PRESENT-{nr}R",
                "block",
                "custom",
                f"PRESENT-80 dual-ECB, {nr}/{_PRESENT_ROUNDS} SPN rounds",
            ),
            num_rounds=nr,
        )

    # Reduced-round Trivium: trivium-288r etc.
    trivium_rr = re.match(r"^trivium-(\d+)r$", normalized)
    if trivium_rr:
        nr = int(trivium_rr.group(1))
        if not 1 <= nr <= 4096:
            raise ValueError(f"Trivium warm-up rounds must be 1-4096, got {nr}")
        return ReducedRoundTriviumWrapper(
            spec=PrimitiveSpec(
                f"Trivium-{nr}R",
                "stream",
                "custom",
                f"Trivium reduced-round warm-up, {nr} clocks before 128-bit keystream extraction",
            ),
            num_rounds=nr,
        )

    # Reduced-round Grain: grain-256r, grain-128-256r, grain-128a-256r etc.
    grain_rr = re.match(r"^grain(?:-128a?)?-(\d+)r$", normalized)
    if grain_rr:
        nr = int(grain_rr.group(1))
        if not 1 <= nr <= 4096:
            raise ValueError(f"Grain warm-up rounds must be 1-4096, got {nr}")
        return ReducedRoundGrainWrapper(
            spec=PrimitiveSpec(
                f"Grain-{nr}R",
                "stream",
                "custom",
                f"Grain-128 reduced-round warm-up, {nr} clocks before 128-bit keystream extraction",
            ),
            num_rounds=nr,
        )

    # Direct-key RC4 control: rc4-direct-256r etc.
    rc4_direct = re.match(r"^rc4-direct-(\d+)r$", normalized)
    if rc4_direct:
        nr = int(rc4_direct.group(1))
        if not 1 <= nr <= 16384:
            raise ValueError(f"RC4 drop rounds must be 1-16384, got {nr}")
        return DirectKeyRC4Wrapper(
            spec=PrimitiveSpec(
                f"RC4-Direct-{nr}R",
                "stream",
                "custom",
                f"RC4 direct 16-byte key perturbation with fixed {nr}-byte drop",
            ),
            num_rounds=nr,
        )

    # Reduced-round hashed RC4: rc4-256r etc.
    rc4_rr = re.match(r"^rc4-(\d+)r$", normalized)
    if rc4_rr:
        nr = int(rc4_rr.group(1))
        if not 1 <= nr <= 16384:
            raise ValueError(f"RC4 drop rounds must be 1-16384, got {nr}")
        return ReducedRoundRC4Wrapper(
            spec=PrimitiveSpec(
                f"RC4-{nr}R",
                "stream",
                "custom",
                f"RC4 reduced-round PRGA drop, {nr} steps before 128-bit keystream extraction",
            ),
            num_rounds=nr,
        )

    # Reduced-round A5/1: a5-1-100r, a5/1-100r etc.
    a51_rr = re.match(r"^a5(?:/|-)?1-(\d+)r$", normalized)
    if a51_rr:
        nr = int(a51_rr.group(1))
        if not 1 <= nr <= 4096:
            raise ValueError(f"A5/1 warm-up rounds must be 1-4096, got {nr}")
        return ReducedRoundA51Wrapper(
            spec=PrimitiveSpec(
                f"A5/1-{nr}R",
                "stream",
                "custom",
                f"A5/1 reduced-round warm-up, {nr} majority clocks before 128-bit extraction",
            ),
            num_rounds=nr,
        )

    # Reduced-round ChaCha20: chacha20-8r, chacha20-12r etc.
    chacha_rr = re.match(r"^chacha20-(\d+)r$", normalized)
    if chacha_rr:
        nr = int(chacha_rr.group(1))
        if not (2 <= nr <= 20 and nr % 2 == 0):
            raise ValueError(f"ChaCha20 round count must be even in 2-20, got {nr}")
        return ReducedRoundChaCha20Wrapper(
            spec=PrimitiveSpec(
                f"ChaCha20-{nr}R",
                "stream",
                "custom",
                f"ChaCha20 core with {nr}/20 rounds",
            ),
            num_rounds=nr,
        )

    # Reduced-round Salsa20: salsa20-8r, salsa20-12r etc.
    salsa_rr = re.match(r"^salsa20-(\d+)r$", normalized)
    if salsa_rr:
        nr = int(salsa_rr.group(1))
        if not (2 <= nr <= 20 and nr % 2 == 0):
            raise ValueError(f"Salsa20 round count must be even in 2-20, got {nr}")
        return ReducedRoundSalsa20Wrapper(
            spec=PrimitiveSpec(
                f"Salsa20-{nr}R",
                "stream",
                "custom",
                f"Salsa20 core with {nr}/20 rounds",
            ),
            num_rounds=nr,
        )

    available = ", ".join(spec.name for spec in list_primitive_specs())
    raise ValueError(f"Unsupported primitive '{name}'. Available: {available}")
