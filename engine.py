# -*- coding: utf-8 -*-
"""
Frida 解密引擎：注入运行中的 QQ音乐，调用客户端原生解密能力。
- 附加 QQMusic 进程
- 加载 JS，调用 QQMusicCommon.dll 的 EncAndDesMediaFile
- 读取 MMKV 中的 ekey
"""
import os
import sys
import time
import frida


JS_CODE = r"""
'use strict';

const QM_DLL = 'QQMusicCommon.dll';
const MMKV_DLL = 'mmkv.dll';

// 全局持有分配的内存，防止被 GC 回收
const held = [];
let lastData = null;

function findModule(namePart) {
    const mods = Process.enumerateModules();
    for (const m of mods) {
        if (m.name.toLowerCase().indexOf(namePart.toLowerCase()) !== -1) {
            return m;
        }
    }
    return null;
}

rpc.exports = {
    ping: function () {
        return {
            pid: Process.id,
            arch: Process.arch,
            modules: Process.enumerateModules().map(m => m.name).slice(0, 50)
        };
    },

    modules: function () {
        return Process.enumerateModules().map(m => ({ name: m.name, base: m.base.toString(), size: m.size }));
    },

    // 读取 MMKV 中指定 id 的全部键
    getekeys: function (mmkvId) {
        return new Promise(function (resolve, reject) {
            try {
                const mmkvMod = findModule('mmkv');
                if (!mmkvMod) { resolve({ error: 'mmkv.dll not found' }); return; }

                // MMKV::mmkvWithID(const std::string&)
                const mmkvWithID = Module.findExportByName(mmkvMod.name, '?mmkvWithID@MMKV@@SA?AV?$shared_ptr@VMMKV@@@std@@AEBV?$basic_string@DU?$char_traits@D@std@@@2@Z')
                    || Module.findExportByName(mmkvMod.name, 'mmkvWithID');
                if (!mmkvWithID) { resolve({ error: 'mmkvWithID export not found' }); return; }

                // 构造 std::string（MSVC 布局，简化处理）
                const idStr = mmkvId || 'MMKVStatic';
                const strBuf = Memory.alloc(0x20);
                held.push(strBuf);
                // 调用 std::string 构造（这里借助 MSVC ABI，直接写短字符串优化缓冲区）
                const stdStringCtor = Module.findExportByName(mmkvMod.name, '??0?$basic_string@DU?$char_traits@D@std@@@std@@QEAA@PEBD@Z');
                if (stdStringCtor) {
                    const ctor = new NativeFunction(stdStringCtor, 'pointer', ['pointer', 'pointer']);
                    const cstr = Memory.allocUtf8String(idStr);
                    held.push(cstr);
                    ctor(strBuf, cstr);
                }

                const fn = new NativeFunction(mmkvWithID, 'pointer', ['pointer']);
                const sharedPtr = fn(strBuf);
                held.push(sharedPtr);
                // shared_ptr 第一个字段是 MMKV 对象指针
                const mmkvObj = sharedPtr.readPointer();
                if (mmkvObj.isNull()) { resolve({ error: 'MMKV object null' }); return; }

                // allKeys
                const allKeysExp = Module.findExportByName(mmkvMod.name, '?allKeys@MMKV@@QEAA?AV?$basic_string@DU?$char_traits@D@std@@@std@@XZ');
                const getStringExp = Module.findExportByName(mmkvMod.name, '?getString@MMKV@@QEAA?AV?$basic_string@DU?$char_traits@D@std@@@std@@AEBV21@PEBD@Z');

                if (!allKeysExp) { resolve({ error: 'allKeys not found' }); return; }

                // 延迟一点保证异步初始化
                setTimeout(function () {
                    try {
                        const allKeysFn = new NativeFunction(allKeysExp, 'pointer', ['pointer'], 'thiscall');
                        const keysVec = allKeysFn(mmkvObj);
                        held.push(keysVec);
                        // std::vector<std::string> 布局：begin, end, cap
                        const begin = keysVec.readPointer();
                        const end = keysVec.add(Process.pointerSize).readPointer();
                        const count = (end.sub(begin).toInt32()) / 0x20;
                        const result = {};
                        for (let i = 0; i < count; i++) {
                            const keyObj = begin.add(i * 0x20);
                            // std::string 短串优化：缓冲在对象内
                            let keyStr, valStr;
                            const keyCap = keyObj.add(0x10).readUShort();
                            if (keyCap > 15) {
                                keyStr = keyObj.readPointer().readUtf8String();
                            } else {
                                keyStr = keyObj.readUtf8String();
                            }
                            if (getStringExp && keyStr) {
                                const getFn = new NativeFunction(getStringExp, 'pointer', ['pointer', 'pointer', 'pointer'], 'thiscall');
                                const defBuf = Memory.alloc(0x20);
                                held.push(defBuf);
                                const keyCstr = Memory.allocUtf8String(keyStr);
                                held.push(keyCstr);
                                const valObj = getFn(mmkvObj, keyCstr, defBuf);
                                held.push(valObj);
                                const valCap = valObj.add(0x10).readUShort();
                                if (valCap > 15) {
                                    valStr = valObj.readPointer().readUtf8String();
                                } else {
                                    valStr = valObj.readUtf8String();
                                }
                                result[keyStr] = valStr;
                            }
                        }
                        resolve({ keys: Object.keys(result), map: result, count: count });
                    } catch (e) {
                        resolve({ error: String(e) });
                    }
                }, 300);
            } catch (e) {
                resolve({ error: String(e) });
            }
        });
    },

    // 解密单个文件：调用 EncAndDesMediaFile
    decrypt: function (filePath) {
        return new Promise(function (resolve, reject) {
            try {
                const dll = findModule('QQMusicCommon');
                if (!dll) { resolve({ error: 'QQMusicCommon.dll not found' }); return; }

                // 查找 EncAndDesMediaFile 构造/Open/Read/GetSize
                const ctorExp = Module.findExportByName(dll.name, '??0EncAndDesMediaFile@@QEAA@XZ');
                const openExp = Module.findExportByName(dll.name, '?Open@EncAndDesMediaFile@@QEAA_NPEBD@Z');
                const getSizeExp = Module.findExportByName(dll.name, '?GetSize@EncAndDesMediaFile@@QEAA_KXZ');
                const readExp = Module.findExportByName(dll.name, '?Read@EncAndDesMediaFile@@QEAA_NPEAE_K@Z');
                const dtorExp = Module.findExportByName(dll.name, '??1EncAndDesMediaFile@@QEAA@XZ');

                if (!(ctorExp && openExp && getSizeExp && readExp)) {
                    resolve({ error: 'EncAndDesMediaFile exports not all found' });
                    return;
                }

                const obj = Memory.alloc(0x100);
                held.push(obj);
                const ctor = new NativeFunction(ctorExp, 'void', ['pointer'], 'thiscall');
                const open = new NativeFunction(openExp, 'bool', ['pointer', 'pointer'], 'thiscall');
                const getSize = new NativeFunction(getSizeExp, 'uint64', ['pointer'], 'thiscall');
                const read = new NativeFunction(readExp, 'bool', ['pointer', 'pointer', 'uint64'], 'thiscall');
                const dtor = dtorExp ? new NativeFunction(dtorExp, 'void', ['pointer'], 'thiscall') : null;

                ctor(obj);
                const pathCstr = Memory.allocUtf8String(filePath);
                held.push(pathCstr);
                const ok = open(obj, pathCstr);
                if (!ok) { resolve({ error: 'Open failed', path: filePath }); if (dtor) dtor(obj); return; }

                const size = getSize(obj).toNumber();
                const buf = Memory.alloc(size);
                held.push(buf);
                const rok = read(obj, buf, size);
                if (!rok) { resolve({ error: 'Read failed', path: filePath }); if (dtor) dtor(obj); return; }

                const bytes = buf.readByteArray(size);
                lastData = bytes;
                if (dtor) dtor(obj);
                resolve({ path: filePath, size: size, got: bytes.byteLength });
            } catch (e) {
                resolve({ error: String(e) });
            }
        });
    },

    // 单独取回上次解密的原始字节（顶层 ArrayBuffer，便于 Python 转 bytes）
    decryptdata: function () {
        const d = lastData;
        lastData = null;
        return d;
    }
};
"""


class QQMusicDecryptEngine:
    def __init__(self, log_func=print):
        self.log = log_func
        self.session = None
        self.script = None

    def _find_qqmusic_pid(self):
        for p in frida.enumerate_processes():
            if 'qqmusic' in p.name.lower():
                return p.pid, p.name
        return None, None

    def attach(self):
        pid, name = self._find_qqmusic_pid()
        if not pid:
            raise RuntimeError('未发现运行中的 QQ音乐，请先打开并登录 QQ音乐客户端')
        self.log(f'附加进程：{name} (pid={pid})')
        self.session = frida.attach(pid)
        self.script = self.session.create_script(JS_CODE)
        self.script.load()
        info = self.script.exports_sync.ping()
        self.log(f'注入成功，进程架构 {info.get("arch")}，模块数 {len(info.get("modules", []))}')
        return True

    def decrypt_file(self, file_path):
        """返回解密后的原始字节，失败返回 None"""
        res = self.script.exports_sync.decrypt(file_path)
        if 'error' in res:
            self.log(f'  原生解密失败：{res["error"]}')
            return None
        data = self.script.exports_sync.decryptdata()
        if data is None:
            return None
        return data

    def get_all_ekeys(self, mmkv_id='MMKVStatic'):
        res = self.script.exports_sync.getekeys(mmkv_id)
        if 'error' in res:
            self.log(f'  读取 ekey 失败：{res["error"]}')
            return {}
        return res.get('map', {})

    def detach(self):
        try:
            if self.session:
                self.session.detach()
        except Exception:
            pass
