# -*- coding: utf-8 -*-
"""
QQ音乐加密歌曲转MP3工具 - 图形界面
支持 .mflac / .mgg / .qmc 等加密格式，批量转换为 MP3
"""
import os
import sys
import threading
import subprocess
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    from engine import QQMusicDecryptEngine
except Exception:
    QQMusicDecryptEngine = None

try:
    from qmc_core import make_cipher, detect_footer
except Exception:
    make_cipher = None
    detect_footer = None


SUPPORTED_EXT = (".mflac", ".mgg", ".mflac0", ".mflach", ".qmc")
DEFAULT_SRC = r"C:\Users\admin\Music\VipSongsDownload"
DEFAULT_OUT = r"C:\Users\admin\Music\VipSongsDownload_MP3"


def resource_path(rel):
    """兼容 PyInstaller 打包后的资源路径"""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, rel)


class ConverterApp:
    def __init__(self, root):
        self.root = root
        self.root.title("QQ音乐转MP3工具")
        self.root.geometry("720x560")
        self.root.minsize(640, 480)

        self.src_var = tk.StringVar(value=DEFAULT_SRC)
        self.out_var = tk.StringVar(value=DEFAULT_OUT)
        self.running = False
        self.stop_flag = False
        self.engine = None

        self._build_ui()

    def _build_ui(self):
        pad = {"padx": 10, "pady": 6}
        frm = ttk.Frame(self.root)
        frm.pack(fill="both", expand=True, padx=12, pady=10)

        # 源目录
        ttk.Label(frm, text="歌曲文件夹：").grid(row=0, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.src_var).grid(row=0, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="浏览", command=self._pick_src).grid(row=0, column=2, **pad)

        # 输出目录
        ttk.Label(frm, text="输出文件夹：").grid(row=1, column=0, sticky="w", **pad)
        ttk.Entry(frm, textvariable=self.out_var).grid(row=1, column=1, sticky="ew", **pad)
        ttk.Button(frm, text="浏览", command=self._pick_out).grid(row=1, column=2, **pad)

        frm.columnconfigure(1, weight=1)

        # 按钮区
        btn_frm = ttk.Frame(frm)
        btn_frm.grid(row=2, column=0, columnspan=3, pady=8)
        self.start_btn = ttk.Button(btn_frm, text="开始转换", command=self._start)
        self.start_btn.pack(side="left", padx=8)
        self.stop_btn = ttk.Button(btn_frm, text="停止", command=self._stop, state="disabled")
        self.stop_btn.pack(side="left", padx=8)
        ttk.Button(btn_frm, text="打开输出目录", command=self._open_out).pack(side="left", padx=8)

        # 进度条
        self.progress = ttk.Progressbar(frm, mode="determinate")
        self.progress.grid(row=3, column=0, columnspan=3, sticky="ew", padx=10, pady=4)
        self.status_var = tk.StringVar(value="就绪")
        ttk.Label(frm, textvariable=self.status_var).grid(row=4, column=0, columnspan=3, sticky="w", padx=10)

        # 日志
        ttk.Label(frm, text="运行日志：").grid(row=5, column=0, sticky="w", padx=10, pady=(8, 0))
        self.log_box = tk.Text(frm, height=14, wrap="word")
        self.log_box.grid(row=6, column=0, columnspan=3, sticky="nsew", padx=10, pady=6)
        scroll = ttk.Scrollbar(frm, command=self.log_box.yview)
        scroll.grid(row=6, column=3, sticky="ns", pady=6)
        self.log_box.configure(yscrollcommand=scroll.set)
        frm.rowconfigure(6, weight=1)

    # ---------- 选择目录 ----------
    def _pick_src(self):
        d = filedialog.askdirectory(initialdir=self.src_var.get() or os.path.expanduser("~"))
        if d:
            self.src_var.set(d)

    def _pick_out(self):
        d = filedialog.askdirectory(initialdir=self.out_var.get() or os.path.expanduser("~"))
        if d:
            self.out_var.set(d)

    def _open_out(self):
        out = self.out_var.get()
        os.makedirs(out, exist_ok=True)
        if sys.platform.startswith("win"):
            os.startfile(out)
        else:
            subprocess.Popen(["xdg-open", out])

    # ---------- 日志 ----------
    def log(self, msg):
        self.root.after(0, lambda: self._append_log(msg))

    def _append_log(self, msg):
        self.log_box.insert("end", str(msg) + "\n")
        self.log_box.see("end")

    def set_status(self, msg):
        self.root.after(0, lambda: self.status_var.set(msg))

    # ---------- 开始/停止 ----------
    def _start(self):
        src = self.src_var.get().strip()
        out = self.out_var.get().strip()
        if not src or not os.path.isdir(src):
            messagebox.showerror("错误", "请选择有效的歌曲文件夹")
            return
        os.makedirs(out, exist_ok=True)
        self.stop_flag = False
        self.running = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        t = threading.Thread(target=self._run, args=(src, out), daemon=True)
        t.start()

    def _stop(self):
        self.stop_flag = True
        self.set_status("正在停止…")

    # ---------- 主流程 ----------
    def _run(self, src, out):
        files = [f for f in os.listdir(src) if f.lower().endswith(SUPPORTED_EXT)]
        if not files:
            self.log("未找到支持的加密歌曲文件（.mflac/.mgg/.qmc）")
            self._finish()
            return
        total = len(files)
        self.progress.configure(maximum=total, value=0)
        self.log(f"发现 {total} 个待转换文件")

        # 初始化 Frida 引擎
        if QQMusicDecryptEngine is None:
            self.log("警告：Frida 引擎不可用，将仅尝试离线解密")
        else:
            try:
                self.engine = QQMusicDecryptEngine(log_func=self.log)
                self.engine.attach()
            except Exception as e:
                self.log(f"引擎附加失败：{e}")
                self.engine = None

        ekey_map = {}
        if self.engine:
            try:
                ekey_map = self.engine.get_all_ekeys()
                self.log(f"读取到 {len(ekey_map)} 个 ekey")
            except Exception as e:
                self.log(f"读取 ekey 出错：{e}")

        success, fail = 0, 0
        for idx, name in enumerate(files, 1):
            if self.stop_flag:
                self.log("已手动停止")
                break
            path = os.path.join(src, name)
            self.set_status(f"处理中 {idx}/{total}：{name}")
            self.log(f"[{idx}/{total}] {name}")
            try:
                raw = self._decrypt_one(path, name, ekey_map)
                if not raw:
                    self.log("  解密失败，跳过")
                    fail += 1
                else:
                    mp3_path = self._unique_out_path(out, name)
                    if self._encode_mp3(raw, mp3_path):
                        self.log(f"  已保存：{os.path.basename(mp3_path)}")
                        success += 1
                    else:
                        fail += 1
            except Exception as e:
                self.log(f"  异常：{e}")
                fail += 1
            self.progress.configure(value=idx)

        self.log(f"完成：成功 {success} 个，失败 {fail} 个")
        self.set_status(f"完成：成功 {success}，失败 {fail}")
        if self.engine:
            self.engine.detach()
        self._finish()

    def _decrypt_one(self, path, name, ekey_map):
        # 1) 优先 Frida 客户端原生解密
        if self.engine:
            data = self.engine.decrypt_file(path)
            if data and self._looks_like_audio(data):
                return data
            self.log("  常规解密密钥不匹配，启用历史密钥匹配")

        # 2) 离线兜底：读取文件，尝试尾部密钥 / 枚举 ekey
        with open(path, "rb") as f:
            data = f.read()

        if detect_footer and make_cipher:
            key, audio, ftype = detect_footer(data)
            if key:
                cipher = make_cipher(key)
                dec = cipher.decrypt(audio)
                if self._looks_like_audio(dec):
                    return dec

            # 枚举全部 ekey（含历史残留）
            for _k, ekey_b64 in ekey_map.items():
                try:
                    from qmc_core import parse_ekey
                    ckey = parse_ekey(ekey_b64)
                    cipher = make_cipher(ckey)
                    if not cipher:
                        continue
                    dec = cipher.decrypt(data)
                    if self._looks_like_audio(dec):
                        self.log(f"  历史密钥匹配成功（{_k}）")
                        return dec
                except Exception:
                    continue
        return None

    @staticmethod
    def _looks_like_audio(data):
        return data[:4] == b"fLaC" or data[:4] == b"OggS"

    def _encode_mp3(self, raw_audio, mp3_path):
        ffmpeg = self._find_ffmpeg()
        if not ffmpeg:
            self.log("  未找到 ffmpeg，请确认程序完整")
            return False
        cmd = [
            ffmpeg, "-y", "-i", "pipe:0",
            "-codec:a", "libmp3lame", "-b:a", "320k",
            "-ar", "44100", "-ac", "2",
            "-id3v2_version", "3", "-write_id3v1", "1",
            mp3_path
        ]
        proc = subprocess.run(cmd, input=raw_audio, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            self.log("  MP3 编码失败：" + proc.stderr.decode("utf-8", "ignore")[-300:])
            return False
        return True

    def _find_ffmpeg(self):
        candidates = [
            resource_path(os.path.join("bin", "ffmpeg.exe")),
            resource_path("ffmpeg.exe"),
            "ffmpeg",
        ]
        for c in candidates:
            if c == "ffmpeg":
                return c
            if os.path.isfile(c):
                return c
        return None

    @staticmethod
    def _unique_out_path(out, src_name):
        base = os.path.splitext(src_name)[0]
        target = os.path.join(out, base + ".mp3")
        n = 1
        while os.path.exists(target):
            target = os.path.join(out, f"{base}_{n}.mp3")
            n += 1
        return target

    def _finish(self):
        self.running = False
        self.root.after(0, lambda: (
            self.start_btn.configure(state="normal"),
            self.stop_btn.configure(state="disabled")
        ))


def main():
    root = tk.Tk()
    ConverterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
