# -*- coding: utf-8 -*-
"""
QMC 解密核心（纯 Python 实现，无第三方依赖）
包含：
- 腾讯 TEA 算法（16 轮）
- EncV2 密钥派生
- QmcMap / QmcRc4 解密
- 文件尾部识别（musicex / QTag / v1）
"""
import struct
import hashlib

# ---------------- TEA ----------------
DELTA = 0x9E3779B9
MASK = 0xFFFFFFFF


def _tea_encrypt(v, key):
    s = 0
    y, z = v
    out = [y, z]
    for _ in range(16):
        s = (s + DELTA) & MASK
        y = (y + (((z << 4) + key[0]) ^ (z + s) ^ ((z >> 5) + key[1]))) & MASK
        z = (z + (((y << 4) + key[2]) ^ (y + s) ^ ((y >> 5) + key[3]))) & MASK
        out[0], out[1] = y, z
    return out


def _tea_decrypt(v, key):
    y, z = v
    s = (DELTA * 16) & MASK
    for _ in range(16):
        z = (z - (((y << 4) + key[2]) ^ (y + s) ^ ((y >> 5) + key[3]))) & MASK
        y = (y - (((z << 4) + key[0]) ^ (z + s) ^ ((z >> 5) + key[1]))) & MASK
        s = (s - DELTA) & MASK
    return [y, z]


def _bytes_to_ints(b):
    return list(struct.unpack('>%dI' % (len(b) // 4), b))


def _ints_to_bytes(ints):
    return struct.pack('>%dI' % len(ints), *ints)


def _tea_decrypt_ecb(block, key):
    ints = _bytes_to_ints(block)
    dec = _tea_decrypt(ints, key)
    return _ints_to_bytes(dec)


# ---------------- EncV2 密钥派生 ----------------
def parse_ekey(ekey_b64: str) -> bytes:
    """将 base64 形式的 ekey 用 TEA 解密得到原始密钥"""
    import base64
    if not ekey_b64:
        return b''
    raw = base64.b64decode(ekey_b64)
    key = [0x55, 0x6E, 0x6D, 0x61, 0x73, 0x6B, 0x4E, 0x61]
    key_ints = _bytes_to_ints(bytes(key))
    # 每 8 字节解密
    out = b''
    for i in range(0, len(raw), 8):
        out += _tea_decrypt_ecb(raw[i:i + 8], key_ints)
    # 去掉头部填充：首字节表示头部填充长度
    pad_len = out[0] & 0x07
    out = out[pad_len + 1:]
    return out


# ---------------- QmcMap（静态密钥，旧版） ----------------
class QmcMap:
    def __init__(self, key: bytes):
        self.key = key
        self.n = len(key)

    def decrypt(self, data: bytes, offset: int = 0) -> bytes:
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ self.key[(offset + i) % self.n]
        return bytes(out)


# ---------------- QmcRc4（EncV2） ----------------
class QmcRc4:
    def __init__(self, key: bytes):
        self.key = key
        n = len(key)
        box = list(range(256))
        j = 0
        keybuf = key
        for i in range(256):
            j = (box[i] + j + keybuf[i % n]) & 0xFF
            box[i], box[j] = box[j], box[i]
        self.box = box
        # 跳过前 0x300（768）字节，增强 RC4
        self._skip = 0x300
        self._i = 0
        self._j = 0

    def _keystream(self, length):
        box = self.box
        i, j = self._i, self._j
        ks = bytearray()
        remaining = length + self._skip
        count = 0
        while count < remaining:
            i = (i + 1) & 0xFF
            j = (j + box[i]) & 0xFF
            box[i], box[j] = box[j], box[i]
            k = box[(box[i] + box[j]) & 0xFF]
            if count >= self._skip:
                ks.append(k)
            count += 1
        self._i, self._j = i, j
        self._skip = 0
        return bytes(ks)

    def decrypt(self, data: bytes, offset: int = 0) -> bytes:
        ks = self._keystream(len(data))
        return bytes(b ^ k for b, k in zip(data, ks))


def make_cipher(key: bytes):
    """根据密钥长度选择算法：<=300 字节走 QmcMap，否则 QmcRc4"""
    if not key:
        return None
    if len(key) <= 300:
        return QmcMap(key)
    return QmcRc4(key)


# ---------------- 尾部识别 ----------------
MUSIC_EX_MAGIC = b'musicex'
QTAG_MAGIC = b'QTag'


def detect_footer(data: bytes):
    """
    识别文件尾部，返回 (cipher_key, audio_data, footer_type)
    支持：musicex（QMC2）、QTag、以及无尾部的 v1
    """
    if len(data) < 8:
        return None, data, 'unknown'

    # 1) musicex 尾部（QMC2，密钥在尾部 JSON/结构中）
    idx = data.rfind(MUSIC_EX_MAGIC)
    if idx != -1:
        footer = data[idx:]
        key = _parse_musicex_footer(footer)
        if key:
            return key, data[:idx], 'musicex'

    # 2) QTag 尾部
    idx = data.rfind(QTAG_MAGIC)
    if idx != -1:
        footer = data[idx:]
        key = _parse_qtag_footer(footer)
        if key:
            return key, data[:idx], 'QTag'

    # 3) 无尾部 v1：需要外部 ekey，这里返回标识，由调用方处理
    return None, data, 'v1'


def _parse_musicex_footer(footer: bytes):
    """
    musicex 结构（简化）：
    magic(8) + version(4) + ekey_len(4) + ekey(...) + ...
    不同版本字段略有差异，这里做容错解析。
    """
    try:
        if len(footer) < 16:
            return None
        # magic 8 字节，version 4 字节
        ekey_len = struct.unpack('>I', footer[12:16])[0]
        if 0 < ekey_len <= len(footer) - 16:
            ekey_b64 = footer[16:16 + ekey_len].decode('utf-8', 'ignore').strip('\x00')
            return parse_ekey(ekey_b64)
    except Exception:
        return None
    return None


def _parse_qtag_footer(footer: bytes):
    """QTag: magic(4) + version(4) + ekey_len(4) + ekey"""
    try:
        if len(footer) < 12:
            return None
        ekey_len = struct.unpack('>I', footer[8:12])[0]
        if 0 < ekey_len <= len(footer) - 12:
            ekey_b64 = footer[12:12 + ekey_len].decode('utf-8', 'ignore').strip('\x00')
            return parse_ekey(ekey_b64)
    except Exception:
        return None
    return None


def sha1_md5_key(song_id: str, extra: str = ''):
    """部分旧版 v1 文件密钥派生（按歌曲 id），保留备用"""
    return hashlib.md5((song_id + extra).encode()).digest()
