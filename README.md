# QQ音乐转MP3工具（qqmusic-mp3-converter）

把 QQ音乐下载的加密歌曲（`.mflac` / `.mgg` / `.qmc` 等）批量转换为通用 **MP3** 的图形化小工具。转换后可在手机、车机、U盘、任意播放器直接播放。

带图形界面（Tkinter），支持批量处理、自动兜底，无需把账号密码发给任何人。

---

## ✨ 功能特性

- **图形界面**：选好文件夹一键转换，带进度条和实时日志，小白可用。
- **批量转换**：自动识别整个文件夹里的加密歌曲，逐个处理并统计成功/失败。
- **双引擎解密**：
  - 主路径：通过 [Frida](https://frida.re/) 注入运行中的 QQ音乐，调用客户端自身 `QQMusicCommon.dll` 解密，原生速度。
  - 兜底：当客户端当前密钥与文件不匹配时，枚举客户端 MMKV 中全部历史 `ekey`，用纯 Python 算法离线暴力匹配。
- **高质量输出**：统一用 ffmpeg 编码为 **MP3，320kbps、44.1kHz 立体声**。
- **安全私密**：全程在本机运行，不上传文件、不读取账号密码。
- **可打包成 exe**：提供 PyInstaller 配置，可打成独立可执行程序。

## 🎵 支持格式

| 类型 | 扩展名 / 标识 |
|---|---|
| QQ音乐加密文件 | `.mflac`、`.mgg`、`.mflac0`、`.mflach`、`.qmc` |
| 尾部标识 | `musicex`、`QTag`、QMC v1 |
| 解密后源格式 | FLAC（`fLaC`）、Ogg（`OggS`） |
| 最终输出 | MP3（libmp3lame 320kbps） |

## 🧠 工作原理

1. 检测运行中的 QQ音乐进程并 `attach`，注入 JavaScript。
2. 调用客户端 `EncAndDesMediaFile` 类的 `Open / GetSize / Read` 完成解密。
3. 校验解密后文件头（`fLaC` / `OggS`），无效则进入兜底：
   - 读取 MMKV 全部 `ekey`（含历史残留）；
   - 用腾讯 TEA（16 轮）派生密钥，按 QmcMap / QmcRc4 算法逐个尝试，匹配正确文件头。
4. 调用 ffmpeg 把解密后的音频转码为 320kbps MP3。

## 📁 目录结构

```
qqmusic-mp3-converter/
├── main.py                  # 图形界面与转换主流程
├── engine.py                # Frida 注入引擎（客户端解密 + 读取 ekey）
├── qmc_core.py              # 纯 Python 离线解密核心（TEA / QmcMap / QmcRc4 / 尾部识别）
├── QQMusicConverter.spec    # PyInstaller 打包配置
├── requirements.txt         # Python 依赖
├── 使用说明.txt             # 面向普通用户的中文使用说明
└── README.md
```

> `bin/ffmpeg.exe`、打包产物 `dist/`、压缩包等大文件不纳入 Git，已在 `.gitignore` 中忽略。

## 🖥️ 环境要求

- Windows 10 / 11（64 位）
- Python 3.10+（运行源码时需要；Tkinter 为标准库自带）
- 已安装并登录、保持运行的 QQ音乐客户端
- ffmpeg（打包版已内置；源码运行需自行安装或放到 `bin/ffmpeg.exe`）

## 🚀 快速开始

### 方式一：直接使用打包好的 exe（推荐普通用户）

1. 到本仓库的 **Releases** 下载 `QQ音乐转MP3工具.zip`。
2. 完整解压整个文件夹（不要只拖出 exe）。
3. 先打开 QQ音乐并登录、保持运行。
4. 双击 `QQMusicConverter.exe`，选择歌曲文件夹和输出文件夹，点击“开始转换”。

详细步骤与杀毒误报处理见 [`使用说明.txt`](使用说明.txt)。

### 方式二：从源码运行

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 准备 ffmpeg：自行安装并加入 PATH，或放到 bin/ffmpeg.exe

# 3. 先打开 QQ音乐并登录，再运行
python main.py
```

### 方式三：自行打包为 exe

```bash
pip install pyinstaller
pyinstaller QQMusicConverter.spec
```

打包产物在 `dist/` 目录，为 onedir 结构（exe 与 `_internal` 必须放在一起，不可只单独移动 exe）。

## ❓ 常见问题

- **提示“未发现运行中的 QQ音乐”**：先打开 QQ音乐并登录、保持运行，再点开始。
- **日志出现“启用历史密钥匹配”**：正常的自动兜底流程，会稍慢，无需操作。
- **杀毒软件报风险**：未签名打包程序的常见误报，选择“信任/允许”或将文件夹加入白名单。
- **提示“未找到 ffmpeg”**：解压不完整或 `_internal` 被移动/删除，请重新完整解压。
- **个别文件失败**：先确认该歌曲能在 QQ音乐正常播放且已完整下载，仍失败可查看日志排查。

## ⚠️ 免责声明

本工具仅用于**个人已合法获取音乐的格式转换**，方便在不同设备播放。请遵守相关法律法规，不得用于传播、盗版、侵权或任何商业违规用途。转换过程在本地完成，不涉及账号密码与文件上传。

## 📄 许可证

本项目仅供学习与个人使用。
