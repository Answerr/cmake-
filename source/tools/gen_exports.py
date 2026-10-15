#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_exports.py —— 生成代理 DLL 的导出转发层。

读取一个干净系统 DLL（默认 C:\\Windows\\System32\\dbghelp.dll）的导出表，
生成三组文件，让代理 DLL 对每个导出都做"无损转发"：

  exports/dbghelp_proxy.def  链接器模块定义（名字=fp_N 映射，MSVC/MinGW 通用）
  src/forwarding.asm         MASM 跳转桩（MSVC x64 无内联汇编时用）
  src/forwarding_stubs.h     GCC 裸函数桩（MinGW 生产工具链用）
  src/forwarding_count.h     导出数量常量 SD3_NEXPORTS
  src/forwarding_names.h     导出名表（解析器按它从真 DLL 取真实地址）

每个导出落到 fp_<序号>，fp_N 通过 g_fwd[N] 间接跳转。g_fwd 里的指针在
DllMain 阶段由 fwd_resolve() 按绝对路径 LoadLibraryA 加载系统真 DLL 后
逐一填充。

用法：
    python gen_exports.py [C:\\Windows\\System32\\dbghelp.dll]

注意：只有换目标系统 DLL 时才需要重新跑本脚本。
"""
import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def read_export_names(path):
    """遍历 PE 导出目录，返回导出名字列表。"""
    d = open(path, 'rb').read()
    e = struct.unpack('<I', d[0x3C:0x40])[0]
    opt = e + 24
    exp_rva = struct.unpack('<I', d[opt + 112:opt + 116])[0]
    if exp_rva == 0:
        raise SystemExit('目标 DLL 没有导出目录')
    nsec = struct.unpack('<H', d[e + 6:e + 8])[0]
    optsz = struct.unpack('<H', d[e + 20:e + 22])[0]
    sec = e + 24 + optsz

    def rva2off(rva):
        for i in range(nsec):
            o = sec + i * 40
            va, rawsz, rawptr = struct.unpack('<III', d[o + 12:o + 24])
            if va <= rva < va + rawsz:
                return rawptr + (rva - va)
        return None

    eo = rva2off(exp_rva)
    n_names = struct.unpack('<I', d[eo + 0x18:eo + 0x1C])[0]
    aon = struct.unpack('<I', d[eo + 0x20:eo + 0x24])[0]
    no = rva2off(aon)
    names = []
    for i in range(n_names):
        nrva = struct.unpack('<I', d[no + 4 * i:no + 4 * i + 4])[0]
        o2 = rva2off(nrva)
        end = d.find(b'\x00', o2)
        names.append(d[o2:end].decode('ascii'))
    return names


def main():
    sys_dll = sys.argv[1] if len(sys.argv) > 1 else r'C:\Windows\System32\dbghelp.dll'
    names = read_export_names(sys_dll)
    print('%s: 共 %d 个导出' % (sys_dll, len(names)))

    # 1) 模块定义文件（MSVC 与 MinGW 通用）
    os.makedirs(os.path.join(ROOT, 'exports'), exist_ok=True)
    with open(os.path.join(ROOT, 'exports', 'dbghelp_proxy.def'), 'w') as f:
        f.write('LIBRARY dbghelp.dll\nEXPORTS\n')
        for i, n in enumerate(names):
            f.write('    %s=fp_%d\n' % (n, i))
        f.write('    entry_dll\n')

    # 2) MASM 跳转桩（每个导出两条指令：经 g_fwd[] 间接跳转）
    with open(os.path.join(ROOT, 'src', 'forwarding.asm'), 'w') as f:
        f.write('; 由 gen_exports.py 自动生成 —— 请勿手改。\n')
        f.write('; 每个导出是一个两指令跳板：经已解析的指针表 g_fwd[] 跳转\n')
        f.write(';（指针表见 main.c 的 fwd_resolve()）。\n')
        f.write('EXTERN g_fwd:QWORD\n\n')
        f.write('.CODE\n\n')
        for i, n in enumerate(names):
            f.write('fp_%d PROC\n    jmp QWORD PTR [g_fwd + %d*8]\nfp_%d ENDP\n\n' % (i, i, i))
        f.write('END\n')

    # 3) GCC 裸函数桩（MinGW 生产工具链）
    with open(os.path.join(ROOT, 'src', 'forwarding_stubs.h'), 'w') as f:
        f.write('/* 由 gen_exports.py 自动生成 —— 请勿手改。 */\n')
        f.write('#ifndef FORWARDING_STUBS_H\n#define FORWARDING_STUBS_H\n\n')
        for i in range(len(names)):
            f.write('__attribute__((naked)) void fp_%d(void) {\n'
                    '    __asm__ volatile("jmp *%%0" : : "m"(g_fwd[%d]));\n}\n' % (i, i))
        f.write('\n#endif /* FORWARDING_STUBS_H */\n')

    # 4) 导出数量常量（main.c 用它定义 g_fwd 数组大小）
    with open(os.path.join(ROOT, 'src', 'forwarding_count.h'), 'w') as f:
        f.write('/* 由 gen_exports.py 自动生成 —— 请勿手改。 */\n')
        f.write('#define SD3_NEXPORTS %du\n' % len(names))

    # 5) 导出名字表（与 fp_N / g_fwd[] 下标对齐），解析器用它从真 DLL
    #    按名字取真实地址
    with open(os.path.join(ROOT, 'src', 'forwarding_names.h'), 'w') as f:
        f.write('/* 由 gen_exports.py 自动生成 —— 请勿手改。 */\n')
        f.write('static const char* const sd3_export_names[SD3_NEXPORTS] = {\n')
        for n in names:
            f.write('    "%s",\n' % n)
        f.write('};\n')

    print('已生成 exports/dbghelp_proxy.def、src/forwarding.asm、'
          'src/forwarding_stubs.h、src/forwarding_count.h、src/forwarding_names.h')


if __name__ == '__main__':
    main()
