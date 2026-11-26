#!/usr/bin/env python3
"""GTA VI save tool (SARC / ASAV v1, storage mode 3).

Decrypt & decompress:  SARC file  -> JSON body (and optionally the raw JSAV)
Compress & encrypt:    JSON body (or JSAV .bin) + original SARC as template -> new SARC file

ASAV layout (flags 0x180 = encrypted | integrity):
  header   0x170 bytes  (Jenkins checksum, seed 0x4BF672ED, at +0x160; logical end u32 at +0x168)
  payload  AES-256-CTR( raw LZ4 block | PKCS#7 padding ), counter starts at the fixed IV,
           128-bit big-endian increment, one continuous stream over the whole payload
  trailer  32 bytes, plaintext: two-pass SHA-256 resumed from fixed inner/outer prefix states,
           over header + padded ciphertext
  LZ4 output = JSAV v3 (header, 20-byte index, JSON body, NUL padding)

Self-contained, Python 3.8+, stdlib only. Uses the 'cryptography' package for faster AES and the
'lz4' package for faster compression if they happen to be installed.

Usage:
  python gta6_save_tool.py                         (GUI)
  python gta6_save_tool.py decrypt SARC0003 out.json
  python gta6_save_tool.py encrypt body.json SARC0003_original SARC0003_new
"""
import json
import os
import queue
import struct
import sys
import threading
import time


# --------------------------------------------------------------------------------------------
# Constants
# --------------------------------------------------------------------------------------------
M32 = 0xFFFFFFFF
HDR_SIZE = 0x170
TAG_SIZE = 32
JOAAT_SEED = 0x4BF672ED

ASAV_ENCRYPTED = 0x80
ASAV_INTEGRITY = 0x100

# header field offsets
OFF_FLAGS = 0x10
OFF_HDR_SIZE = 0x14
OFF_CLEAR = 0x18        # 0x170 + LZ4 block length (before padding)
OFF_DECODED = 0x1C      # 0x170 + decompressed JSAV length
OFF_CHECKSUM = 0x160
OFF_STORED = 0x168      # logical end: 0x170 + padded ciphertext + 32-byte trailer

SAVE_KEY = bytes.fromhex("76a15074d1daeea87a1d19efac61e8bab3cce5a19658c5f5cb998d2261919eb2")
INITIAL_COUNTER = bytes.fromhex("6370edc3c58aa56eaac4550b68556e06")

INNER_STATE = (0x4710EAAA, 0x037CCC2C, 0x6F0951E4, 0xF47E5CAB,
               0x4336B48A, 0xD406CCBD, 0xFFB06142, 0x3AB12B69)
OUTER_STATE = (0x249F1D72, 0x38AF7FB4, 0xFB751A8B, 0x18CC9974,
               0x1983CA88, 0x9600194A, 0x1F423665, 0x81B17751)


# --------------------------------------------------------------------------------------------
# AES-256 (encrypt direction only; CTR needs nothing else)
# --------------------------------------------------------------------------------------------
_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16")


def _xtime(x):
    return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else x << 1


def _make_tables():
    t0 = []
    for x in range(256):
        s = _SBOX[x]
        s2 = _xtime(s)
        t0.append((s2 << 24) | (s << 16) | (s << 8) | (s2 ^ s))
    ror = lambda v, n: ((v >> n) | (v << (32 - n))) & M32
    return t0, [ror(v, 8) for v in t0], [ror(v, 16) for v in t0], [ror(v, 24) for v in t0]


_T0, _T1, _T2, _T3 = _make_tables()


def _expand_key(key):
    """AES-256 key schedule -> 60 big-endian round-key words."""
    w = list(struct.unpack(">8I", key))
    rcon = 1
    for i in range(8, 60):
        t = w[i - 1]
        if i % 8 == 0:
            t = ((t << 8) | (t >> 24)) & M32
            t = ((_SBOX[t >> 24] << 24) | (_SBOX[(t >> 16) & 255] << 16) |
                 (_SBOX[(t >> 8) & 255] << 8) | _SBOX[t & 255]) ^ (rcon << 24)
            rcon = _xtime(rcon)
        elif i % 8 == 4:
            t = ((_SBOX[t >> 24] << 24) | (_SBOX[(t >> 16) & 255] << 16) |
                 (_SBOX[(t >> 8) & 255] << 8) | _SBOX[t & 255])
        w.append(w[i - 8] ^ t)
    return w


_RK = _expand_key(SAVE_KEY)


def aes256_encrypt_block(block, rk=_RK):
    T0, T1, T2, T3, S = _T0, _T1, _T2, _T3, _SBOX
    s0, s1, s2, s3 = struct.unpack(">4I", block)
    s0 ^= rk[0]; s1 ^= rk[1]; s2 ^= rk[2]; s3 ^= rk[3]
    k = 4
    for _ in range(13):
        t0 = T0[s0 >> 24] ^ T1[(s1 >> 16) & 255] ^ T2[(s2 >> 8) & 255] ^ T3[s3 & 255] ^ rk[k]
        t1 = T0[s1 >> 24] ^ T1[(s2 >> 16) & 255] ^ T2[(s3 >> 8) & 255] ^ T3[s0 & 255] ^ rk[k + 1]
        t2 = T0[s2 >> 24] ^ T1[(s3 >> 16) & 255] ^ T2[(s0 >> 8) & 255] ^ T3[s1 & 255] ^ rk[k + 2]
        t3 = T0[s3 >> 24] ^ T1[(s0 >> 16) & 255] ^ T2[(s1 >> 8) & 255] ^ T3[s2 & 255] ^ rk[k + 3]
        s0, s1, s2, s3 = t0, t1, t2, t3
        k += 4
    return bytes((
        S[s0 >> 24] ^ (rk[56] >> 24), S[(s1 >> 16) & 255] ^ ((rk[56] >> 16) & 255),
        S[(s2 >> 8) & 255] ^ ((rk[56] >> 8) & 255), S[s3 & 255] ^ (rk[56] & 255),
        S[s1 >> 24] ^ (rk[57] >> 24), S[(s2 >> 16) & 255] ^ ((rk[57] >> 16) & 255),
        S[(s3 >> 8) & 255] ^ ((rk[57] >> 8) & 255), S[s0 & 255] ^ (rk[57] & 255),
        S[s2 >> 24] ^ (rk[58] >> 24), S[(s3 >> 16) & 255] ^ ((rk[58] >> 16) & 255),
        S[(s0 >> 8) & 255] ^ ((rk[58] >> 8) & 255), S[s1 & 255] ^ (rk[58] & 255),
        S[s3 >> 24] ^ (rk[59] >> 24), S[(s0 >> 16) & 255] ^ ((rk[59] >> 16) & 255),
        S[(s1 >> 8) & 255] ^ ((rk[59] >> 8) & 255), S[s2 & 255] ^ (rk[59] & 255),
    ))


def _ctr_fast(data):
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception:
        return None
    try:
        c = Cipher(algorithms.AES(SAVE_KEY), modes.CTR(INITIAL_COUNTER)).encryptor()
        return c.update(bytes(data)) + c.finalize()
    except Exception:
        return None


def ctr_crypt(data, progress=None):
    """AES-256-CTR over a complete payload (encrypt == decrypt).

    The counter starts at INITIAL_COUNTER for byte 0 and is incremented as a 128-bit big-endian
    integer after every 16-byte block, continuously over the whole payload.
    """
    n = len(data)
    fast = _ctr_fast(data)
    if fast is not None:
        if progress:
            progress(n, n)
        return fast
    ctr = int.from_bytes(INITIAL_COUNTER, "big")
    mask = (1 << 128) - 1
    out = bytearray()
    step = 0x10000
    for off in range(0, n, step):
        part = data[off:off + step]
        ks = bytearray()
        for _ in range((len(part) + 15) // 16):
            ks += aes256_encrypt_block(ctr.to_bytes(16, "big"))
            ctr = (ctr + 1) & mask
        L = len(part)
        out += (int.from_bytes(part, "little") ^ int.from_bytes(bytes(ks[:L]), "little")).to_bytes(L, "little")
        if progress:
            progress(min(off + step, n), n)
    return bytes(out)


def pkcs7_pad(data):
    n = 16 - (len(data) % 16)
    return data + bytes([n]) * n


def pkcs7_unpad(data):
    """Returns the unpadded data, or None if the padding is invalid."""
    if not data or len(data) % 16:
        return None
    n = data[-1]
    if n == 0 or n > 16 or data[-n:] != bytes([n]) * n:
        return None
    return data[:-n]


# --------------------------------------------------------------------------------------------
# Integrity trailer: two-pass SHA-256 resumed from fixed 64-byte prefix states
# --------------------------------------------------------------------------------------------
_K256 = (
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
)


def _sha256_compress(state, block):
    w = list(struct.unpack(">16I", block))
    for i in range(16, 64):
        x, y = w[i - 15], w[i - 2]
        s0 = ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3)
        s1 = ((y >> 17) | (y << 15)) ^ ((y >> 19) | (y << 13)) ^ (y >> 10)
        w.append((w[i - 16] + s0 + w[i - 7] + s1) & M32)
    a, b, c, d, e, f, g, h = state
    for i in range(64):
        S1 = (((e >> 6) | (e << 26)) ^ ((e >> 11) | (e << 21)) ^ ((e >> 25) | (e << 7))) & M32
        ch = (e & f) ^ (~e & g)
        t1 = (h + S1 + ch + _K256[i] + w[i]) & M32
        S0 = (((a >> 2) | (a << 30)) ^ ((a >> 13) | (a << 19)) ^ ((a >> 22) | (a << 10))) & M32
        maj = (a & b) ^ (a & c) ^ (b & c)
        h, g, f, e, d, c, b, a = g, f, e, (d + t1) & M32, c, b, a, (t1 + S0 + maj) & M32
    return [(x + y) & M32 for x, y in zip(state, (a, b, c, d, e, f, g, h))]


def sha256_resume(initial_state, message):
    """SHA-256 continued from a state that has already absorbed one 64-byte block."""
    state = list(initial_state)
    total = 64 + len(message)
    padded = bytes(message) + b"\x80" + b"\0" * ((56 - (total + 1) % 64) % 64)
    padded += ((total * 8) & ((1 << 64) - 1)).to_bytes(8, "big")
    mv = memoryview(padded)
    for i in range(0, len(padded), 64):
        state = _sha256_compress(state, mv[i:i + 64])
    return b"".join(x.to_bytes(4, "big") for x in state)


def save_tag(covered, progress=None):
    """32-byte integrity trailer over (serialized header + padded ciphertext)."""
    inner = sha256_resume(INNER_STATE, covered)
    if progress:
        progress(1, 1)
    return sha256_resume(OUTER_STATE, inner)


# --------------------------------------------------------------------------------------------
# ASAV header
# --------------------------------------------------------------------------------------------
def joaat_signed(data, seed=JOAAT_SEED):
    """Jenkins one-at-a-time over *signed* bytes, seeded."""
    x = seed
    for c in data:
        if c > 127:
            c -= 256
        x = (x + c) & M32
        x = (x + (x << 10)) & M32
        x ^= x >> 6
    x = (x + (x << 3)) & M32
    x ^= x >> 11
    x = (x + (x << 15)) & M32
    return x


def header_checksum(hdr):
    h = bytearray(hdr[:HDR_SIZE])
    h[OFF_CHECKSUM:OFF_CHECKSUM + 4] = b"\0\0\0\0"
    return joaat_signed(bytes(h))


def parse_header(raw):
    if len(raw) < HDR_SIZE or raw[:4] != b"ASAV":
        raise ValueError("not an ASAV/SARC save (bad magic)")
    ver, kind, mode, flags, hdr_size, clear, decoded = struct.unpack_from("<7I", raw, 4)
    if hdr_size != HDR_SIZE:
        raise ValueError("unexpected ASAV header size 0x%X" % hdr_size)
    ts = struct.unpack_from("<Q", raw, 0x20)[0]
    title = raw[0x28:0x128].decode("utf-16-le", "replace").split("\0")[0]
    slot = raw[0x128:0x160].split(b"\0")[0].decode("ascii", "replace")
    csum = struct.unpack_from("<I", raw, OFF_CHECKSUM)[0]
    stored = struct.unpack_from("<I", raw, OFF_STORED)[0]
    return dict(version=ver, kind=kind, mode=mode, flags=flags, header_size=hdr_size, clear=clear,
                decoded=decoded, timestamp=ts, title=title, slot=slot, checksum=csum, stored=stored,
                checksum_ok=(csum == header_checksum(raw)))


def _trailer_size(flags):
    return TAG_SIZE if flags & (ASAV_ENCRYPTED | ASAV_INTEGRITY) else 0


# --------------------------------------------------------------------------------------------
# LZ4 raw block
# --------------------------------------------------------------------------------------------
def lz4_decompress(s):
    o = bytearray()
    i, n = 0, len(s)
    while i < n:
        t = s[i]; i += 1
        L = t >> 4
        if L == 15:
            while True:
                b = s[i]; i += 1; L += b
                if b != 255:
                    break
        o += s[i:i + L]; i += L
        if i >= n:
            break
        off = s[i] | (s[i + 1] << 8); i += 2
        M = t & 15
        if M == 15:
            while True:
                b = s[i]; i += 1; M += b
                if b != 255:
                    break
        M += 4
        if off == 0 or off > len(o):
            raise ValueError("bad LZ4 offset %d at input 0x%x" % (off, i))
        start = len(o) - off
        if off >= M:
            o += o[start:start + M]
        else:
            for k in range(M):
                o.append(o[start + k])
    if i != n:
        raise ValueError("LZ4 stream did not end cleanly")
    return bytes(o)


def _lz4_len(out, v):
    while v >= 255:
        out.append(255); v -= 255
    out.append(v)


def lz4_compress(src):
    try:
        import lz4.block  # optional fast path
        return lz4.block.compress(src, mode="high_compression", compression=9, store_size=False)
    except Exception:
        pass
    n = len(src)
    out = bytearray()
    anchor = 0
    end = n - 5            # matches must stop 5 bytes before the end
    limit = n - 12         # last match must start at least 12 bytes before the end
    ht = {}
    i = 0
    while i < limit:
        key = src[i:i + 4]
        ref = ht.get(key)
        ht[key] = i
        if ref is None or i - ref > 0xFFFF:
            i += 1
            continue
        while i > anchor and ref > 0 and src[i - 1] == src[ref - 1]:
            i -= 1; ref -= 1
        j, r = i + 4, ref + 4
        while j + 32 <= end and src[j:j + 32] == src[r:r + 32]:
            j += 32; r += 32
        while j < end and src[j] == src[r]:
            j += 1; r += 1
        lit = src[anchor:i]
        L, ml = len(lit), j - i - 4
        out.append((min(L, 15) << 4) | min(ml, 15))
        if L >= 15:
            _lz4_len(out, L - 15)
        out += lit
        out += struct.pack("<H", i - ref)
        if ml >= 15:
            _lz4_len(out, ml - 15)
        if j - 2 > i:
            ht[src[j - 2:j + 2]] = j - 2
        i = anchor = j
    lit = src[anchor:]
    L = len(lit)
    out.append(min(L, 15) << 4)
    if L >= 15:
        _lz4_len(out, L - 15)
    out += lit
    return bytes(out)


# --------------------------------------------------------------------------------------------
# JSAV v3
# --------------------------------------------------------------------------------------------
BODY_MAGIC = b'{"CodeSaveBlocks":['


def parse_jsav(jsav):
    """Validate a JSAV blob. Returns (info dict, body bytes)."""
    magic, ver, nc, ns = struct.unpack_from("<4sIII", jsav, 0)
    if magic != b"JSAV":
        raise ValueError("decompressed data is not JSAV")
    if ver != 3:
        raise ValueError("unexpected JSAV version %d" % ver)
    bad = 0
    for k in range(nc + ns):
        h, fl, _, off, sz = struct.unpack_from("<5I", jsav, 16 + 20 * k)
        try:
            blk = json.loads(jsav[off:off + sz])
            inner = next(iter(blk.values()))
            if next(iter(inner)) != "$0x%08x" % h:
                bad += 1
        except Exception:
            bad += 1
    bs = jsav.find(BODY_MAGIC)
    if bs < 0:
        raise ValueError("JSON body not found in JSAV")
    body = jsav[bs:].rstrip(b"\0")
    doc = json.loads(body)
    info = dict(version=ver, code=nc, script=ns, index_bad=bad,
                body_code=len(doc.get("CodeSaveBlocks", [])), body_script=len(doc.get("ScriptSaveBlocks", [])),
                body_size=len(body))
    return info, body


def _spans(s, key, dec):
    k = s.find('"%s"' % key)
    if k < 0:
        raise ValueError("missing %s" % key)
    i = s.index("[", k) + 1
    spans = []
    while True:
        while s[i] in " \t\r\n,":
            i += 1
        if s[i] == "]":
            return spans
        obj, e = dec.raw_decode(s, i)
        inner = next(iter(obj.values()))
        h = next(iter(inner))
        if not (isinstance(h, str) and h.startswith("$0x")):
            raise ValueError("block at char %d has no $0x hash key" % i)
        spans.append((i, e, int(h[3:], 16)))
        i = e


def build_jsav(body):
    """Rebuild a JSAV v3 blob (header + index + body) from the JSON body text."""
    body = body.rstrip(b"\0")
    if body.startswith(b"\xef\xbb\xbf"):
        body = body[3:]
    s = body.decode("utf-8")
    json.loads(s)  # must be valid JSON
    dec = json.JSONDecoder()
    code = _spans(s, "CodeSaveBlocks", dec)
    script = _spans(s, "ScriptSaveBlocks", dec)
    ents = code + script
    nents = len(ents)
    idx_end = 16 + 20 * nents
    body_off = (idx_end + 15) & ~15
    ascii_only = s.isascii()
    out = bytearray(struct.pack("<4sIII", b"JSAV", 3, len(code), len(script)))
    pos_c, pos_b = 0, 0  # incremental char->byte offset for non-ASCII text
    for a, e, h in ents:
        if ascii_only:
            ba, be = a, e
        else:
            pos_b += len(s[pos_c:a].encode("utf-8")); pos_c = a; ba = pos_b
            be = ba + len(s[a:e].encode("utf-8"))
        out += struct.pack("<5I", h, 1, 0, body_off + ba, be - ba)
    out += b"\0" * (body_off - len(out))
    out += body
    out += b"\0" * (16 - (len(out) % 16))   # NUL terminator + 16-byte alignment
    return bytes(out)




# --------------------------------------------------------------------------------------------
# Pipelines
# --------------------------------------------------------------------------------------------
def _open_payload(raw, log=lambda m: None, progress=None):
    """Header + integrity check + decrypt + unpad. Returns (hdr, lz4 block, report dict)."""
    hdr = parse_header(raw)
    flags = hdr["flags"]
    trailer = _trailer_size(flags)
    end = hdr["stored"]
    if end > len(raw) or end < HDR_SIZE + trailer:
        raise ValueError("stored length 0x%X does not fit the file (0x%X bytes)" % (end, len(raw)))
    ct = raw[HDR_SIZE:end - trailer]
    if flags & ASAV_ENCRYPTED and (not ct or len(ct) % 16):
        raise ValueError("encrypted payload length 0x%X is not a positive multiple of 16" % len(ct))

    tag_ok = None
    if flags & ASAV_INTEGRITY:
        t = time.time()
        tag_ok = save_tag(raw[:end - TAG_SIZE]) == raw[end - TAG_SIZE:end]
        log("  integrity trailer: %s (%.1fs)" % ("OK" if tag_ok else "MISMATCH", time.time() - t))

    pad_ok = True
    if flags & ASAV_ENCRYPTED:
        t = time.time()
        plain = ctr_crypt(ct, progress)
        log("Decrypted 0x%X bytes (AES-256-CTR) in %.1fs" % (len(ct), time.time() - t))
        comp = pkcs7_unpad(plain)
        pad_ok = comp is not None
        log("  PKCS#7 padding: %s" % ("%d bytes OK" % plain[-1] if pad_ok else "INVALID"))
        if not pad_ok:
            comp = plain
    else:
        comp = ct
        log("  payload is not encrypted (flags 0x%X)" % flags)
    return hdr, comp, dict(tag_ok=tag_ok, pad_ok=pad_ok)


def decrypt_save(raw, log=print, progress=None):
    """Returns (jsav, body, report dict)."""
    hdr = parse_header(raw)
    log("Header: ASAV v%d kind=%d mode=%d flags=0x%X slot=%s title=%r"
        % (hdr["version"], hdr["kind"], hdr["mode"], hdr["flags"], hdr["slot"], hdr["title"]))
    log("  clear=0x%X decoded=0x%X stored(end)=0x%X (file 0x%X)"
        % (hdr["clear"], hdr["decoded"], hdr["stored"], len(raw)))
    log("  header checksum 0x%08X: %s" % (hdr["checksum"], "OK" if hdr["checksum_ok"] else "MISMATCH"))
    if hdr["mode"] != 3:
        log("  warning: storage mode %d (tool was built for mode 3)" % hdr["mode"])
    hdr, comp, rep = _open_payload(raw, log, progress)
    clear_ok = HDR_SIZE + len(comp) == hdr["clear"]
    if not clear_ok:
        log("  warning: clear size 0x%X != 0x170 + LZ4 block 0x%X" % (hdr["clear"], len(comp)))
    jsav = lz4_decompress(comp)
    size_ok = len(jsav) + HDR_SIZE == hdr["decoded"]
    log("LZ4: 0x%X -> 0x%X bytes, size check (0x170 + JSAV == decoded): %s"
        % (len(comp), len(jsav), "OK" if size_ok else "MISMATCH"))
    info, body = parse_jsav(jsav)
    log("JSAV v%d: %d code + %d script blocks, index entries bad: %d"
        % (info["version"], info["code"], info["script"], info["index_bad"]))
    log("Body JSON valid: 0x%X bytes, %d CodeSaveBlocks / %d ScriptSaveBlocks"
        % (info["body_size"], info["body_code"], info["body_script"]))
    ok = (hdr["checksum_ok"] and rep["pad_ok"] and rep["tag_ok"] is not False and clear_ok and size_ok
          and info["index_bad"] == 0
          and info["body_code"] == info["code"] and info["body_script"] == info["script"])
    end = hdr["stored"]
    return jsav, body, dict(ok=ok, header=hdr, lz4=comp, tag_ok=rep["tag_ok"],
                            tag=raw[end - TAG_SIZE:end] if _trailer_size(hdr["flags"]) else b"")


def encrypt_save(src, template_raw, log=print, progress=None):
    """src = JSON body or JSAV bytes; template_raw = original SARC (header fields and storage slot)."""
    hdr = parse_header(template_raw)
    flags = hdr["flags"]
    if not hdr["checksum_ok"]:
        log("warning: template header checksum does not match")
    if not flags & ASAV_ENCRYPTED:
        log("warning: template flags 0x%X have no encryption bit; payload will be stored unencrypted" % flags)
    if src[:4] == b"JSAV":
        jsav = src
        log("Input is a JSAV blob (0x%X bytes), using as-is" % len(jsav))
    else:
        jsav = build_jsav(src)
        log("Built JSAV from JSON body: 0x%X bytes" % len(jsav))
    info, _ = parse_jsav(jsav)
    log("  %d code + %d script blocks, index entries bad: %d" % (info["code"], info["script"], info["index_bad"]))
    if info["index_bad"]:
        raise ValueError("JSAV index does not match its blocks")

    # Reuse the original LZ4 block when the data is unchanged (byte-identical rebuild).
    comp = None
    try:
        _, tpl_comp, tpl_rep = _open_payload(template_raw)
        if tpl_rep["pad_ok"] and lz4_decompress(tpl_comp) == jsav:
            comp = tpl_comp
            log("Data unchanged from the original: reusing its LZ4 block")
    except Exception:
        pass
    if comp is None:
        t = time.time()
        comp = lz4_compress(jsav)
        log("LZ4 compressed 0x%X -> 0x%X bytes in %.1fs" % (len(jsav), len(comp), time.time() - t))
        if lz4_decompress(comp) != jsav:
            raise RuntimeError("LZ4 self-check failed")

    trailer = _trailer_size(flags)
    if flags & ASAV_ENCRYPTED:
        payload = pkcs7_pad(comp)
        t = time.time()
        ct = ctr_crypt(payload, progress)
        log("Padded with %d bytes, encrypted 0x%X bytes (AES-256-CTR) in %.1fs"
            % (len(payload) - len(comp), len(ct), time.time() - t))
    else:
        ct = comp
    new_end = HDR_SIZE + len(ct) + trailer
    if new_end > M32:
        raise ValueError("payload exceeds the ASAV length limit")

    # Keep the original physical slot size if it extends beyond the logical end.
    old_end = hdr["stored"]
    out_size = new_end
    if len(template_raw) > old_end and len(template_raw) > new_end:
        out_size = len(template_raw)
    out = bytearray(template_raw[:out_size])
    out += b"\0" * (out_size - len(out))

    h = bytearray(template_raw[:HDR_SIZE])
    struct.pack_into("<I", h, OFF_CLEAR, HDR_SIZE + len(comp))
    if flags & ASAV_ENCRYPTED:
        struct.pack_into("<I", h, OFF_DECODED, HDR_SIZE + len(jsav))
    struct.pack_into("<I", h, OFF_STORED, new_end)
    struct.pack_into("<I", h, OFF_CHECKSUM, header_checksum(bytes(h)))
    out[:HDR_SIZE] = h
    out[HDR_SIZE:HDR_SIZE + len(ct)] = ct
    if trailer:
        out[new_end - TAG_SIZE:new_end] = template_raw[old_end - TAG_SIZE:old_end]
    if flags & ASAV_INTEGRITY:
        t = time.time()
        out[new_end - TAG_SIZE:new_end] = save_tag(bytes(out[:new_end - TAG_SIZE]))
        log("Integrity trailer computed in %.1fs" % (time.time() - t))
    out = bytes(out)
    log("Header: clear=0x%X decoded=0x%X stored(end)=0x%X file=0x%X checksum=0x%08X"
        % (HDR_SIZE + len(comp), HDR_SIZE + len(jsav), new_end, len(out),
           struct.unpack_from("<I", h, OFF_CHECKSUM)[0]))

    log("Verifying by decrypting the result...")
    jsav2, _, rep = decrypt_save(out, log=lambda m: None)
    ok = rep["ok"] and jsav2 == jsav
    log("Round-trip check: %s" % ("OK" if ok else "FAILED"))
    if out == template_raw:
        log("Output is byte-identical to the original save.")
    return out, ok


# --------------------------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------------------------
def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    root = tk.Tk()
    root.title("GTA VI Save Tool")
    root.minsize(700, 480)
    try:
        ttk.Style().theme_use("vista" if sys.platform == "win32" else "clam")
    except Exception:
        pass

    mode = tk.StringVar(value="decrypt")
    in_path, tpl_path, out_path = tk.StringVar(), tk.StringVar(), tk.StringVar()
    save_jsav = tk.BooleanVar(value=False)
    status = tk.StringVar(value="Ready")
    q = queue.Queue()

    frm = ttk.Frame(root, padding=12)
    frm.pack(fill="both", expand=True)
    frm.columnconfigure(1, weight=1)

    mf = ttk.LabelFrame(frm, text="Operation", padding=8)
    mf.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 8))
    ttk.Radiobutton(mf, text="Decrypt && decompress  (SARC save -> JSON)", variable=mode, value="decrypt",
                    command=lambda: refresh()).pack(anchor="w")
    ttk.Radiobutton(mf, text="Compress && encrypt  (JSON -> SARC save)", variable=mode, value="encrypt",
                    command=lambda: refresh()).pack(anchor="w")

    def default_out():
        p = in_path.get()
        if not p:
            return
        if mode.get() == "decrypt":
            out_path.set(p + "_body.json")
        else:
            base = tpl_path.get() or p
            out_path.set(os.path.join(os.path.dirname(base), os.path.basename(base).split(".")[0] + "_new"))

    def browse_in():
        if mode.get() == "decrypt":
            p = filedialog.askopenfilename(title="Encrypted SARC save")
        else:
            p = filedialog.askopenfilename(title="JSON body or JSAV",
                                           filetypes=[("JSON / JSAV", "*.json *.bin"), ("All files", "*.*")])
        if p:
            in_path.set(p); default_out()

    def browse_tpl():
        p = filedialog.askopenfilename(title="Original SARC save (header template)")
        if p:
            tpl_path.set(p); default_out()

    def browse_out():
        if mode.get() == "decrypt":
            p = filedialog.asksaveasfilename(title="Save JSON as", defaultextension=".json",
                                             filetypes=[("JSON", "*.json"), ("All files", "*.*")])
        else:
            p = filedialog.asksaveasfilename(title="Save SARC as")
        if p:
            out_path.set(p)

    lbl_in = ttk.Label(frm, text="Input:")
    lbl_in.grid(row=1, column=0, sticky="w")
    ttk.Entry(frm, textvariable=in_path).grid(row=1, column=1, sticky="ew", padx=6, pady=3)
    ttk.Button(frm, text="Browse...", command=browse_in).grid(row=1, column=2)
    lbl_tpl = ttk.Label(frm, text="Original save:")
    ent_tpl = ttk.Entry(frm, textvariable=tpl_path)
    btn_tpl = ttk.Button(frm, text="Browse...", command=browse_tpl)
    ttk.Label(frm, text="Output:").grid(row=3, column=0, sticky="w")
    ttk.Entry(frm, textvariable=out_path).grid(row=3, column=1, sticky="ew", padx=6, pady=3)
    ttk.Button(frm, text="Browse...", command=browse_out).grid(row=3, column=2)
    chk = ttk.Checkbutton(frm, text="Also save raw JSAV (.jsav.bin)", variable=save_jsav)

    bar = ttk.Frame(frm)
    bar.grid(row=5, column=0, columnspan=3, sticky="ew", pady=8)
    bar.columnconfigure(1, weight=1)
    run_btn = ttk.Button(bar, text="Run", command=lambda: start())
    run_btn.grid(row=0, column=0)
    pb = ttk.Progressbar(bar, mode="determinate", maximum=1000)
    pb.grid(row=0, column=1, sticky="ew", padx=8)
    ttk.Label(bar, textvariable=status, width=22).grid(row=0, column=2)

    logf = ttk.LabelFrame(frm, text="Log / validation", padding=4)
    logf.grid(row=6, column=0, columnspan=3, sticky="nsew")
    frm.rowconfigure(6, weight=1)
    txt = tk.Text(logf, height=16, wrap="word", font=("Consolas", 9))
    sb = ttk.Scrollbar(logf, command=txt.yview)
    txt.configure(yscrollcommand=sb.set)
    txt.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")

    def refresh():
        if mode.get() == "encrypt":
            lbl_in.configure(text="JSON / JSAV:")
            lbl_tpl.grid(row=2, column=0, sticky="w")
            ent_tpl.grid(row=2, column=1, sticky="ew", padx=6, pady=3)
            btn_tpl.grid(row=2, column=2)
            chk.grid_remove()
        else:
            lbl_in.configure(text="SARC save:")
            lbl_tpl.grid_remove(); ent_tpl.grid_remove(); btn_tpl.grid_remove()
            chk.grid(row=4, column=1, sticky="w", padx=6)
        default_out()

    def log(m):
        q.put(("log", m))

    def prog(d, n):
        q.put(("prog", d / max(n, 1)))

    def worker(m, inp, tpl, outp, want_jsav):
        try:
            data = open(inp, "rb").read()
            if m == "decrypt":
                jsav, body, rep = decrypt_save(data, log, prog)
                open(outp, "wb").write(body)
                log("Wrote JSON body: %s" % outp)
                if want_jsav:
                    jp = os.path.splitext(outp)[0] + ".jsav.bin"
                    open(jp, "wb").write(jsav)
                    log("Wrote JSAV: %s" % jp)
                ok = rep["ok"]
            else:
                out, ok = encrypt_save(data, open(tpl, "rb").read(), log, prog)
                open(outp, "wb").write(out)
                log("Wrote save: %s (0x%X bytes)" % (outp, len(out)))
            q.put(("done", ok))
        except Exception as e:
            log("ERROR: %s: %s" % (type(e).__name__, e))
            q.put(("done", None))

    def start():
        m, inp, tpl, outp = mode.get(), in_path.get(), tpl_path.get(), out_path.get()
        if not inp or not os.path.isfile(inp):
            messagebox.showerror("Input", "Choose an input file."); return
        if m == "encrypt" and (not tpl or not os.path.isfile(tpl)):
            messagebox.showerror("Original save", "Choose the original SARC save (used as the header template)."); return
        if not outp:
            messagebox.showerror("Output", "Choose an output path."); return
        if os.path.abspath(outp) in (os.path.abspath(inp), os.path.abspath(tpl or inp)):
            messagebox.showerror("Output", "Output must not overwrite an input file."); return
        txt.delete("1.0", "end")
        pb["value"] = 0
        status.set("Working...")
        run_btn.state(["disabled"])
        threading.Thread(target=worker, args=(m, inp, tpl, outp, save_jsav.get()), daemon=True).start()

    def pump():
        try:
            while True:
                kind, v = q.get_nowait()
                if kind == "log":
                    txt.insert("end", v + "\n"); txt.see("end")
                elif kind == "prog":
                    pb["value"] = v * 1000
                elif kind == "done":
                    run_btn.state(["!disabled"])
                    pb["value"] = 1000 if v is not None else 0
                    status.set("Done - all checks OK" if v else ("Done - check warnings" if v is False else "Failed"))
        except queue.Empty:
            pass
        root.after(80, pump)

    refresh()
    pump()
    root.mainloop()


def main(argv):
    if len(argv) >= 2 and argv[1] == "decrypt" and len(argv) == 4:
        jsav, body, rep = decrypt_save(open(argv[2], "rb").read())
        open(argv[3], "wb").write(body)
        print("wrote", argv[3], "OK" if rep["ok"] else "WITH WARNINGS")
        return 0 if rep["ok"] else 1
    if len(argv) >= 2 and argv[1] == "encrypt" and len(argv) == 5:
        out, ok = encrypt_save(open(argv[2], "rb").read(), open(argv[3], "rb").read())
        open(argv[4], "wb").write(out)
        print("wrote", argv[4], "OK" if ok else "WITH WARNINGS")
        return 0 if ok else 1
    if len(argv) > 1:
        print(__doc__)
        return 2
    run_gui()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
