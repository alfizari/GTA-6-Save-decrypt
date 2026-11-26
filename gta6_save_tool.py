#!/usr/bin/env python3
"""GTA VI save tool (SARC / ASAV v1, storage mode 3).

Decrypt & decompress:  SARC file  -> JSON body (and optionally the raw JSAV)
Compress & encrypt:    JSON body (or JSAV .bin) + original SARC as template -> new SARC file

Pipeline (see handoff.md):
  ASAV header 0x170 bytes (joaat checksum at +0x160)
  payload @0x170 = Path-A whitebox block cipher in CTR mode, counter = BE128(base_iv) + (offset >> 4),
                   restarted per 64 KiB chunk
  plaintext      = raw LZ4 block (no frame) | PKCS#7 padding | 32-byte trailer tag
  LZ4 output     = JSAV v3 (header, 20-byte index, JSON body, NUL padding)

Self-contained: the cipher tables are embedded below. Python 3.8+, stdlib only
(uses the 'lz4' package for faster compression if it happens to be installed).

Usage:
  python gta6_save_tool.py                         (GUI)
  python gta6_save_tool.py decrypt SARC0003 out.json
  python gta6_save_tool.py encrypt body.json SARC0003_original SARC0003_new
"""
import base64
import hashlib
import json
import os
import queue
import struct
import sys
import threading
import time
import zlib

_TABLES_B64 = (
    "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"
    "1fvlY3Dtw8WKpW6qxFULaFVuBordUVI="
)
_TABLES_SHA256 = "0c2fa9e9fa74b98e7abfb3e6490cf82bf89e78320f51fc93d27b4d7b22807a40"


# --------------------------------------------------------------------------------------------
# Cipher (Path A, key 0xC303000000 / key table entry 23, block form "C")
# --------------------------------------------------------------------------------------------
M32 = 0xFFFFFFFF
HDR_SIZE = 0x170
CHUNK = 0x10000
TAG_SIZE = 32
JOAAT_SEED = 0x4BF672ED


def _load_tables():
    raw = zlib.decompress(base64.b64decode("".join(_TABLES_B64)))
    if hashlib.sha256(raw).hexdigest() != _TABLES_SHA256:
        raise RuntimeError("embedded cipher tables are corrupt")
    B = raw[0:4096]
    T = struct.unpack("<4096I", raw[4096:20480])
    T = [T[i * 256:(i + 1) * 256] for i in range(16)]
    rk = struct.unpack("<60I", raw[20480:20720])
    P = raw[20720:24816]
    iv = raw[24816:24832]
    return B, T, rk, P, iv


_B, _T, _RK, _P, BASE_IV = _load_tables()
BASE_INT = int.from_bytes(BASE_IV, "big")


def _block(a):
    """One block of the whitebox cipher (keystream generator)."""
    B, rk, P = _B, _RK, _P
    T0, T1, T2, T3, T4, T5, T6, T7, T8, T9, T10, T11, T12, T13, T14, T15 = _T
    v6 = (rk[0] ^ B[a[3] + 768] ^ ((B[a[2] + 512] ^ ((B[a[1] + 256] ^ (B[a[0]] << 8)) << 8)) << 8)) & M32
    v7 = (rk[1] ^ B[a[7] + 1792] ^ ((B[a[6] + 1536] ^ ((B[a[5] + 1280] ^ (B[a[4] + 1024] << 8)) << 8)) << 8)) & M32
    v8 = (rk[2] ^ B[a[11] + 2816] ^ ((B[a[10] + 2560] ^ ((B[a[9] + 2304] ^ (B[a[8] + 2048] << 8)) << 8)) << 8)) & M32
    v9 = (rk[3] ^ B[a[15] + 3840] ^ ((B[a[14] + 3584] ^ ((B[a[13] + 3328] ^ (B[a[12] + 3072] << 8)) << 8)) << 8)) & M32
    rki = 4
    for half in range(7):
        v11 = v6
        v12 = v7 & 0xFFFF
        v13 = rk[rki] ^ T15[v9 & 255] ^ T0[(v6 >> 24) & 255] ^ T10[(v8 >> 8) & 255] ^ T5[(v7 >> 16) & 255]
        v14 = rk[rki + 1] ^ T3[v6 & 255] ^ T4[(v7 >> 24) & 255] ^ T9[(v8 >> 16) & 255] ^ T14[(v9 >> 8) & 255]
        v16 = rk[rki + 2] ^ T7[v12 & 255] ^ T8[(v8 >> 24) & 255] ^ T2[(v11 >> 8) & 255] ^ T13[(v9 >> 16) & 255]
        v15 = v9 >> 24
        v17 = T6[(v12 >> 8) & 255]
        v18 = v11 >> 16
        a11 = T11[v8 & 255]
        a12 = T12[v15 & 255]
        a1_ = T1[v18 & 255]
        v22 = rk[rki + 3] ^ a11 ^ a12 ^ a1_ ^ v17
        v19, v20, v21 = v14, v16, v13
        if half == 6:
            break
        rki += 4
        s = (rk[rki - 1] ^ a11 ^ a12 ^ a1_ ^ v17) & 0xFF
        v6 = rk[rki] ^ T15[s] ^ T0[(v13 >> 24) & 255] ^ T10[(v20 >> 8) & 255] ^ T5[(v19 >> 16) & 255]
        v7 = rk[rki + 1] ^ T3[v21 & 255] ^ T4[(v19 >> 24) & 255] ^ T9[(v20 >> 16) & 255] ^ T14[(v22 >> 8) & 255]
        v8 = rk[rki + 2] ^ T7[v19 & 255] ^ T8[(v20 >> 24) & 255] ^ T13[(v22 >> 16) & 255] ^ T2[(v21 >> 8) & 255]
        v9 = rk[rki + 3] ^ T11[v20 & 255] ^ T12[(v22 >> 24) & 255] ^ T6[(v19 >> 8) & 255] ^ T1[(v21 >> 16) & 255]
        rki += 4
    f0, f1, f2, f3 = v21, v19, v20, v22
    return bytes((
        P[0 + ((f0 >> 24) & 255)], P[256 + ((f1 >> 16) & 255)], P[512 + ((f2 >> 8) & 255)], P[768 + (f3 & 255)],
        P[1024 + ((f1 >> 24) & 255)], P[1280 + ((f2 >> 16) & 255)], P[1536 + ((f3 >> 8) & 255)], P[1792 + (f0 & 255)],
        P[2048 + ((f2 >> 24) & 255)], P[2304 + ((f3 >> 16) & 255)], P[2560 + ((f0 >> 8) & 255)], P[2816 + (f1 & 255)],
        P[3072 + ((f3 >> 24) & 255)], P[3328 + ((f0 >> 16) & 255)], P[3584 + ((f1 >> 8) & 255)], P[3840 + (f2 & 255)],
    ))


def ctr_crypt(data, progress=None, offset=0):
    """Encrypt == decrypt. data starts at payload offset `offset` (64 KiB aligned; payload = file 0x170..)."""
    assert offset % CHUNK == 0
    out = bytearray()
    n = len(data)
    mask = (1 << 128) - 1
    for off in range(0, n, CHUNK):
        part = data[off:off + CHUNK]
        ctr = (BASE_INT + ((offset + off) >> 4)) & mask
        ks = bytearray()
        for _ in range((len(part) + 15) // 16):
            ks += _block(ctr.to_bytes(16, "big"))
            ctr = (ctr + 1) & mask
        L = len(part)
        x = int.from_bytes(part, "little") ^ int.from_bytes(bytes(ks[:L]), "little")
        out += x.to_bytes(L, "little")
        if progress:
            progress(min(off + CHUNK, n), n)
    return bytes(out)


# --------------------------------------------------------------------------------------------
# ASAV header
# --------------------------------------------------------------------------------------------
def joaat_signed(data, seed=JOAAT_SEED):
    """sub_144DD1900: Jenkins one-at-a-time over *signed* bytes, seeded."""
    x = seed
    for c in data:
        if c > 127:
            c -= 256
        x = (x + c) & M32
        x = (x + (x << 10)) & M32
        x ^= x >> 6
    x = (x * 9) & M32
    x ^= x >> 11
    x = (x + (x << 15)) & M32
    return x


def header_checksum(hdr):
    h = bytearray(hdr[:HDR_SIZE])
    h[0x160:0x164] = b"\0\0\0\0"
    return joaat_signed(bytes(h))


def parse_header(raw):
    if len(raw) < HDR_SIZE or raw[:4] != b"ASAV":
        raise ValueError("not an ASAV/SARC save (bad magic)")
    ver, kind, mode, f10, payload_off, stored, unpacked = struct.unpack_from("<7I", raw, 4)
    ts = struct.unpack_from("<Q", raw, 0x20)[0]
    title = raw[0x28:0x128].decode("utf-16-le", "replace").split("\0")[0]
    slot = raw[0x128:0x160].split(b"\0")[0].decode("ascii", "replace")
    csum = struct.unpack_from("<I", raw, 0x160)[0]
    fsize = struct.unpack_from("<Q", raw, 0x168)[0]
    return dict(version=ver, kind=kind, mode=mode, f10=f10, payload_off=payload_off, stored=stored,
                unpacked=unpacked, timestamp=ts, title=title, slot=slot, checksum=csum, file_size=fsize,
                checksum_ok=(csum == header_checksum(raw)))


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
def decrypt_save(raw, log=print, progress=None):
    """Returns (jsav, body, report dict)."""
    hdr = parse_header(raw)
    log("Header: ASAV v%d kind=%d mode=%d slot=%s title=%r" % (hdr["version"], hdr["kind"], hdr["mode"],
                                                               hdr["slot"], hdr["title"]))
    log("  stored=0x%X unpacked=0x%X file_size=0x%X (actual 0x%X)" % (hdr["stored"], hdr["unpacked"],
                                                                      hdr["file_size"], len(raw)))
    log("  header checksum 0x%08X: %s" % (hdr["checksum"], "OK" if hdr["checksum_ok"] else "MISMATCH"))
    if hdr["mode"] != 3:
        log("  warning: storage mode %d (tool was built for mode 3)" % hdr["mode"])
    t = time.time()
    plain = ctr_crypt(raw[HDR_SIZE:], progress)
    log("Decrypted 0x%X bytes in %.1fs" % (len(plain), time.time() - t))
    comp_len = hdr["stored"] - HDR_SIZE
    if not (0 < comp_len <= len(plain)):
        raise ValueError("stored size 0x%X does not fit the file" % hdr["stored"])
    pad = plain[comp_len:len(plain) - TAG_SIZE]
    pad_ok = len(pad) > 0 and all(b == len(pad) for b in pad)
    log("  trailer: %d padding bytes (%s) + 32-byte tag" % (len(pad), "PKCS#7 OK" if pad_ok else "unexpected"))
    jsav = lz4_decompress(plain[:comp_len])
    size_ok = len(jsav) + HDR_SIZE == hdr["unpacked"]
    log("LZ4: 0x%X -> 0x%X bytes, size check (0x170 + JSAV == unpacked): %s"
        % (comp_len, len(jsav), "OK" if size_ok else "MISMATCH"))
    info, body = parse_jsav(jsav)
    log("JSAV v%d: %d code + %d script blocks, index entries bad: %d"
        % (info["version"], info["code"], info["script"], info["index_bad"]))
    log("Body JSON valid: 0x%X bytes, %d CodeSaveBlocks / %d ScriptSaveBlocks"
        % (info["body_size"], info["body_code"], info["body_script"]))
    ok = (hdr["checksum_ok"] and pad_ok and size_ok and info["index_bad"] == 0
          and info["body_code"] == info["code"] and info["body_script"] == info["script"])
    return jsav, body, dict(ok=ok, header=hdr, tag=plain[-TAG_SIZE:])


# --------------------------------------------------------------------------------------------
# Native tag generation: run the game's own keyed-hash by manually mapping the exe.
# The 32-byte save tag is produced by a whitebox hash with a static key inside the exe.
# We map game_scarlett_master.exe into this process and call its generate(init/update/final).
# Windows x64 only; returns None on any failure so the caller can fall back.
# --------------------------------------------------------------------------------------------
PREFERRED_BASE = 0x140000000
_TAG_INIT_RVA = 0x145603F60 - PREFERRED_BASE   # generate init (key 0x400000000 / magic 0x65F27725)
_TAG_UPD_RVA = 0x145604100 - PREFERRED_BASE
_TAG_FIN_RVA = 0x145604180 - PREFERRED_BASE    # writes 32-byte tag
_TAG_BLOB_RVA = 0x1466FD190 - PREFERRED_BASE
_TAG_OK = 564457155

# Common install locations for the game executable; the GUI can override.
DEFAULT_EXE_PATHS = [
    r"C:\Users\omant\Desktop\game_scarlett_master.exe",
]

_NATIVE_CACHE = {}


def _map_exe(exe_path):
    """Manually map the PE (sections, base relocs, imports; Xbox-only DLLs stubbed). Returns base or raises."""
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32
    k32.VirtualAlloc.restype = ctypes.c_void_p
    k32.VirtualAlloc.argtypes = [ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    k32.LoadLibraryA.restype = ctypes.c_void_p
    k32.LoadLibraryA.argtypes = [ctypes.c_char_p]
    k32.GetProcAddress.restype = ctypes.c_void_p
    k32.GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    COMMIT_RESERVE, RWX = 0x3000, 0x40

    data = open(exe_path, "rb").read()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    coff = pe + 4
    nsec = struct.unpack_from("<H", data, coff + 2)[0]
    optsz = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    image_size = struct.unpack_from("<I", data, opt + 56)[0]
    reloc_rva, reloc_sz = struct.unpack_from("<II", data, opt + 112 + 5 * 8)
    imp_rva = struct.unpack_from("<II", data, opt + 112 + 1 * 8)[0]
    sectab = opt + optsz

    base = k32.VirtualAlloc(ctypes.c_void_p(PREFERRED_BASE), image_size, COMMIT_RESERVE, RWX) \
        or k32.VirtualAlloc(None, image_size, COMMIT_RESERVE, RWX)
    if not base:
        raise OSError("VirtualAlloc failed")
    base = int(base)
    ctypes.memmove(base, data, 0x1000)
    for i in range(nsec):
        s = sectab + i * 40
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, s + 8)
        n = min(rawsize, vsize) if vsize else rawsize
        if n:
            ctypes.memmove(base + vaddr, data[rawptr:rawptr + n], n)

    delta = base - PREFERRED_BASE
    if delta and reloc_rva and reloc_sz:
        off, end = reloc_rva, reloc_rva + reloc_sz
        while off < end:
            page_rva, block = struct.unpack("<II", ctypes.string_at(base + off, 8))
            if block == 0:
                break
            for j in range((block - 8) // 2):
                e = struct.unpack_from("<H", ctypes.string_at(base + off + 8 + j * 2, 2))[0]
                if (e >> 12) == 10:
                    a = base + page_rva + (e & 0xFFF)
                    v = struct.unpack("<Q", ctypes.string_at(a, 8))[0]
                    ctypes.memmove(a, struct.pack("<Q", (v + delta) & 0xFFFFFFFFFFFFFFFF), 8)
            off += block

    stub = k32.VirtualAlloc(None, 0x1000, COMMIT_RESERVE, RWX)
    ctypes.memmove(stub, bytes.fromhex("31c0c3"), 3)   # xor eax,eax; ret
    off = imp_rva
    while True:
        ilt, _ts, _fc, name_rva, iat = struct.unpack("<IIIII", ctypes.string_at(base + off, 20))
        if name_rva == 0 and iat == 0:
            break
        h = k32.LoadLibraryA(ctypes.string_at(base + name_rva))
        thunk = ilt if ilt else iat
        k = 0
        while True:
            ent = struct.unpack("<Q", ctypes.string_at(base + thunk + k * 8, 8))[0]
            if ent == 0:
                break
            proc = 0
            if h:
                if ent & (1 << 63):
                    proc = k32.GetProcAddress(h, ctypes.c_char_p(ent & 0xFFFF))
                else:
                    proc = k32.GetProcAddress(h, ctypes.string_at(base + (ent & 0x7FFFFFFF) + 2))
            ctypes.memmove(base + iat + k * 8, struct.pack("<Q", int(proc) if proc else int(stub)), 8)
            k += 1
        off += 20
    return base


def native_tag(message, exe_path):
    """Return the 32-byte save tag computed by the game's own hash, or None on failure."""
    try:
        import ctypes
        base = _NATIVE_CACHE.get(exe_path)
        if base is None:
            base = _map_exe(exe_path)
            _NATIVE_CACHE[exe_path] = base
        init = ctypes.CFUNCTYPE(ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)(base + _TAG_INIT_RVA)
        upd = ctypes.CFUNCTYPE(ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64)(base + _TAG_UPD_RVA)
        fin = ctypes.CFUNCTYPE(ctypes.c_uint, ctypes.c_void_p, ctypes.c_void_p)(base + _TAG_FIN_RVA)
        ctxp = ctypes.c_void_p(0)
        if init(ctypes.c_void_p(base + _TAG_BLOB_RVA), ctypes.byref(ctxp)) != _TAG_OK:
            return None
        buf = ctypes.create_string_buffer(bytes(message), len(message)) if message else ctypes.create_string_buffer(1)
        if upd(ctxp, buf, len(message)) != _TAG_OK:
            return None
        out = ctypes.create_string_buffer(32)
        if fin(ctxp, out) != _TAG_OK:
            return None
        return out.raw[:32]
    except Exception:
        return None


def find_default_exe():
    for p in DEFAULT_EXE_PATHS:
        if os.path.isfile(p):
            return p
    return ""


_DLL = {}


def dll_tag(message):
    """Compute the tag via the tiny standalone helper gta6_tag.dll (no game exe). None on failure."""
    try:
        import ctypes
        if "fn" not in _DLL:
            here = os.path.dirname(os.path.abspath(__file__))
            dll_path = os.path.join(here, "gta6_tag.dll")
            blob = os.path.join(here, "gta6_tag_blob.bin")
            if not (os.path.isfile(dll_path) and os.path.isfile(blob)):
                _DLL["fn"] = None
                return None
            d = ctypes.CDLL(dll_path)
            d.compute_tag.restype = ctypes.c_int
            d.compute_tag.argtypes = [ctypes.c_char_p, ctypes.c_uint64, ctypes.c_char_p]
            _DLL["fn"] = d.compute_tag
        fn = _DLL["fn"]
        if fn is None:
            return None
        out = ctypes.create_string_buffer(32)
        if fn(bytes(message), len(message), out) != 0:
            return None
        return out.raw[:32]
    except Exception:
        return None


def encrypt_save(src, template_raw, log=print, progress=None, exe_path=None):
    """src = JSON body or JSAV bytes; template_raw = original SARC (header fields, and tag fallback)."""
    hdr = parse_header(template_raw)
    if not hdr["checksum_ok"]:
        log("warning: template header checksum does not match")
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

    t = time.time()
    comp = lz4_compress(jsav)
    log("LZ4 compressed 0x%X -> 0x%X bytes in %.1fs" % (len(jsav), len(comp), time.time() - t))
    if lz4_decompress(comp) != jsav:
        raise RuntimeError("LZ4 self-check failed")
    padn = 16 - (len(comp) % 16)
    payload = comp + bytes([padn]) * padn          # comp + PKCS#7 pad; the tag goes right after this

    # tag: the game hashes the payload (comp + pad); generate it with the game's own hash if we can.
    tag = None
    tag_source = "copied from original"
    # 1) tiny standalone helper DLL (no 120 MB exe needed)
    tag = dll_tag(payload)
    if tag is not None:
        tag_source = "generated by gta6_tag.dll (standalone helper)"
    # 2) full game exe, if a path was given
    if tag is None and exe_path and os.path.isfile(exe_path):
        log("Generating tag with the game's hash (%s)..." % os.path.basename(exe_path))
        tag = native_tag(payload, exe_path)
        if tag is not None:
            tag_source = "generated natively from the game exe"
        else:
            log("  native tag generation failed; falling back to copying from the original.")
    if tag is None:
        tpl_payload = template_raw[HDR_SIZE:]
        last = (len(tpl_payload) - 1) // CHUNK * CHUNK
        tag = ctr_crypt(tpl_payload[last:], offset=last)[-TAG_SIZE:]
    plain = payload + tag
    t = time.time()
    ct = ctr_crypt(plain, progress)
    log("Encrypted 0x%X bytes in %.1fs" % (len(ct), time.time() - t))

    h = bytearray(template_raw[:HDR_SIZE])
    struct.pack_into("<I", h, 0x18, HDR_SIZE + len(comp))
    struct.pack_into("<I", h, 0x1C, HDR_SIZE + len(jsav))
    struct.pack_into("<Q", h, 0x168, HDR_SIZE + len(ct))
    struct.pack_into("<I", h, 0x160, header_checksum(bytes(h)))
    out = bytes(h) + ct
    log("Header: stored=0x%X unpacked=0x%X file_size=0x%X checksum=0x%08X"
        % (HDR_SIZE + len(comp), HDR_SIZE + len(jsav), len(out), struct.unpack_from("<I", h, 0x160)[0]))

    log("Verifying by decrypting the result...")
    jsav2, _, rep = decrypt_save(out, log=lambda m: None)
    ok = rep["ok"] and jsav2 == jsav
    log("Round-trip check: %s" % ("OK" if ok else "FAILED"))
    log("Tag: %s." % tag_source)
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
    exe_path = tk.StringVar(value=find_default_exe())
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

    def browse_exe():
        p = filedialog.askopenfilename(title="Game executable (for tag generation)",
                                       filetypes=[("Executable", "*.exe"), ("All files", "*.*")])
        if p:
            exe_path.set(p)

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
    lbl_exe = ttk.Label(frm, text="Game .exe (tag):")
    ent_exe = ttk.Entry(frm, textvariable=exe_path)
    btn_exe = ttk.Button(frm, text="Browse...", command=browse_exe)

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
            lbl_exe.grid(row=4, column=0, sticky="w")
            ent_exe.grid(row=4, column=1, sticky="ew", padx=6, pady=3)
            btn_exe.grid(row=4, column=2)
        else:
            lbl_in.configure(text="SARC save:")
            lbl_tpl.grid_remove(); ent_tpl.grid_remove(); btn_tpl.grid_remove()
            lbl_exe.grid_remove(); ent_exe.grid_remove(); btn_exe.grid_remove()
            chk.grid(row=4, column=1, sticky="w", padx=6)
        default_out()

    def log(m):
        q.put(("log", m))

    def prog(d, n):
        q.put(("prog", d / max(n, 1)))

    def worker(m, inp, tpl, outp, want_jsav, exe):
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
                out, ok = encrypt_save(data, open(tpl, "rb").read(), log, prog, exe_path=exe or None)
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
            messagebox.showerror("Original save", "Choose the original SARC save (used for header and trailer)."); return
        if not outp:
            messagebox.showerror("Output", "Choose an output path."); return
        if os.path.abspath(outp) in (os.path.abspath(inp), os.path.abspath(tpl or inp)):
            messagebox.showerror("Output", "Output must not overwrite an input file."); return
        exe = exe_path.get().strip()
        if m == "encrypt" and exe and not os.path.isfile(exe):
            messagebox.showerror("Game .exe", "The game .exe path is set but not found. Clear it to copy the tag instead, or fix the path."); return
        txt.delete("1.0", "end")
        pb["value"] = 0
        status.set("Working...")
        run_btn.state(["disabled"])
        threading.Thread(target=worker, args=(m, inp, tpl, outp, save_jsav.get(), exe), daemon=True).start()

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
    if len(argv) >= 2 and argv[1] == "encrypt" and len(argv) in (5, 6):
        exe = argv[5] if len(argv) == 6 else find_default_exe()
        out, ok = encrypt_save(open(argv[2], "rb").read(), open(argv[3], "rb").read(), exe_path=exe or None)
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
