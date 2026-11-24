#!/usr/bin/env python3
"""Local packet oscilloscope with live capture and EtherCAT PDO analog step-waveform visualization."""

import atexit
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

BASE = Path(__file__).resolve().parent
STATIC = BASE / "static"
HOST = "127.0.0.1"
PORT = 8765
CHANNEL_COUNT = 20
MAX_BODY = 1024 * 1024

def get_wireshark_candidates():
    candidates = [
        Path("/Applications/Wireshark.app/Contents/MacOS"),
        Path("/usr/local/bin"),
        Path("/opt/homebrew/bin"),
        Path(r"C:\Program Files\Wireshark"),
        Path(r"C:\Program Files (x86)\Wireshark"),
        Path(r"D:\Program Files\Wireshark"),
        Path(r"D:\Program Files (x86)\Wireshark"),
        Path(r"D:\02_ProgramFile\Wireshark"),
        Path(r"C:\02_ProgramFile\Wireshark"),
    ]
    # 加入所在磁碟常見路徑
    if os.name == "nt" and BASE.drive:
        candidates.extend([
            Path(f"{BASE.drive}\\Program Files\\Wireshark"),
            Path(f"{BASE.drive}\\02_ProgramFile\\Wireshark"),
            Path(f"{BASE.drive}\\Wireshark"),
        ])
    # 檢查環境變數
    for env_var in ("WIRESHARK_PATH", "WIRESHARK_HOME", "WIRESHARK_DIR"):
        val = os.environ.get(env_var)
        if val:
            candidates.append(Path(val))
    for pf in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramW6432")):
        if pf:
            candidates.append(Path(pf) / "Wireshark")
   # Windows 機碼查詢 Wireshark 安裝目錄
    if os.name == "nt":
        try:
            import winreg
            for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
                for subkey in (
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Wireshark.exe",
                    r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\tshark.exe",
                ):
                    try:
                        with winreg.OpenKey(root, subkey) as key:
                            path_val, _ = winreg.QueryValueEx(key, "Path")
                            if path_val:
                                for p in str(path_val).split(";"):
                                    if p.strip():
                                        candidates.append(Path(p.strip()))
                    except OSError:
                        pass
                    try:
                        with winreg.OpenKey(root, subkey) as key:
                            default_val, _ = winreg.QueryValueEx(key, "")
                            if default_val:
                                candidates.append(Path(default_val).parent)
                    except OSError:
                        pass
                for subkey in (r"SOFTWARE\Wireshark", r"SOFTWARE\WOW6432Node\Wireshark"):
                    try:
                        with winreg.OpenKey(root, subkey) as key:
                            for val_name in ("InstallDir", "Path", "Install_Dir", "InstallLocation"):
                                try:
                                    val, _ = winreg.QueryValueEx(key, val_name)
                                    if val:
                                        candidates.append(Path(val))
                                except OSError:
                                    pass
                    except OSError:
                        pass
        except Exception:
            pass
    seen = set()
    unique = []
    for c in candidates:
        try:
            if c.is_dir():
                resolved = c.resolve()
                if resolved not in seen:
                    seen.add(resolved)
                    unique.append(resolved)
        except Exception:
            pass
    return unique

APP_CANDIDATES = get_wireshark_candidates()

def find_tool(name):
    # 1. 優先檢查系統 PATH
    found = shutil.which(name)
    if found:
        return found
    if os.name == "nt" and not name.lower().endswith(".exe"):
        found = shutil.which(f"{name}.exe")
        if found:
            return found
    # 2. 檢查各候選目錄（Windows 機碼、macOS 應用程式目錄、常用自訂路徑等）
    exe_name = f"{name}.exe" if os.name == "nt" else name
    for directory in APP_CANDIDATES:
        candidate = directory / exe_name
        if candidate.is_file():
            return str(candidate)
    return exe_name


TSHARK = find_tool("tshark")
CAPINFOS = find_tool("capinfos")
CAPTURE_SUFFIXES = {".pcap", ".pcapng"}
LIVE_FILENAME = "live_capture.pcap"

CAPTURE_LOCK = threading.Lock()
CAPTURE_PROC = None
CAPTURE_INTERFACE = None


def stop_live_capture():
    global CAPTURE_PROC, CAPTURE_INTERFACE
    with CAPTURE_LOCK:
        if CAPTURE_PROC is not None:
            if CAPTURE_PROC.poll() is None:
                CAPTURE_PROC.terminate()
                try:
                    CAPTURE_PROC.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    CAPTURE_PROC.kill()
            CAPTURE_PROC = None
        CAPTURE_INTERFACE = None


atexit.register(stop_live_capture)


def list_interfaces():
    try:
        proc = subprocess.run(
            [TSHARK, "-D"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return []

    interfaces = []
    for line in proc.stdout.splitlines():
        match = re.match(r"^(\d+)\.\s+(.+)$", line.strip())
        if match:
            interfaces.append({"id": match.group(1), "name": match.group(2)})
    if not interfaces and proc.returncode != 0:
        err = proc.stderr.strip()
        raise RuntimeError(err or "無法取得網路介面清單")
    return interfaces


def start_live_capture(interface_id):
    global CAPTURE_PROC, CAPTURE_INTERFACE
    stop_live_capture()
    live_path = BASE / LIVE_FILENAME
    if live_path.exists():
        try:
            live_path.unlink()
        except OSError:
            pass

    with CAPTURE_LOCK:
        cmd = [
            TSHARK,
            "-i",
            str(interface_id),
            "-F",
            "pcap",
            "-w",
            str(live_path),
        ]
        try:
            CAPTURE_PROC = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
        except FileNotFoundError:
            raise RuntimeError(f"找不到 {TSHARK}，請確認已安裝 Wireshark 或設定 WIRESHARK_PATH 環境變數")
        CAPTURE_INTERFACE = str(interface_id)

    time.sleep(0.5)
    with CAPTURE_LOCK:
        if CAPTURE_PROC and CAPTURE_PROC.poll() is not None:
            err = CAPTURE_PROC.stderr.read().strip() if CAPTURE_PROC.stderr else ""
            CAPTURE_PROC = None
            CAPTURE_INTERFACE = None
            raise RuntimeError(err or "啟動即時抓包失敗，請確認執行權限或網卡設定")

    return {"file": LIVE_FILENAME, "interface": interface_id}


def capture_status():
    with CAPTURE_LOCK:
        running = CAPTURE_PROC is not None and CAPTURE_PROC.poll() is None
        return {
            "running": running,
            "interface": CAPTURE_INTERFACE if running else None,
            "file": LIVE_FILENAME if running else None,
        }


def list_captures():
    files = [
        path
        for path in BASE.iterdir()
        if path.is_file() and path.suffix.lower() in CAPTURE_SUFFIXES
    ]
    files.sort(key=lambda path: path.stat().st_mtime, reverse=True)
    return [path.name for path in files]


def resolve_capture(name):
    if not name or name != Path(name).name:
        raise ValueError("檔名不合法")
    path = (BASE / name).resolve()
    if path.parent != BASE or path.suffix.lower() not in CAPTURE_SUFFIXES:
        raise ValueError("檔名不合法")
    if not path.is_file():
        raise ValueError("找不到檔案")
    return path


def capture_meta(path, fallback_duration=None):
    proc = None
    try:
        proc = subprocess.run(
            [CAPINFOS, str(path)],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        if fallback_duration is None:
            raise RuntimeError(f"找不到 {CAPINFOS}，請確認已安裝 Wireshark 或設定 WIRESHARK_PATH 環境變數")
    packets = 0
    duration = None
    if proc is not None:
        for line in proc.stdout.splitlines():
            if line.startswith("Number of packets:"):
                try:
                    packets = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif line.startswith("Capture duration:"):
                try:
                    duration = float(line.split(":", 1)[1].strip().split()[0])
                except ValueError:
                    pass

    if duration is None:
        if fallback_duration is not None:
            duration = fallback_duration
        else:
            duration = 1.0
    if duration <= 0:
        duration = 1e-6
    return {"file": path.name, "packets": packets, "duration": duration}


# --- EtherCAT PDO 解析與波形點位產生引擎 (一律 Little-Endian) ---
PDO_TYPES = {
    "bit": (1, None),
    "bool": (1, None),
    "uint8": (1, "<B"),
    "int8": (1, "<b"),
    "uint16": (2, "<H"),
    "int16": (2, "<h"),
    "uint32": (4, "<I"),
    "int32": (4, "<i"),
    "uint64": (8, "<Q"),
    "int64": (8, "<q"),
    "float": (4, "<f"),
    "float32": (4, "<f"),
    "double": (8, "<d"),
    "float64": (8, "<d"),
}


def parse_pdo_rule(raw_filter):
    """
    解析 pdo: 語法
    格式 1: pdo: <基礎過濾> | <byte_offset> | <type> [| <datagram_index>]
    格式 2 (支援 bit): pdo: <基礎過濾> | <byte_offset>.<bit_index> | bit [| <datagram_index>]
    格式 3 (原始 Hex): pdo: <基礎過濾> | <byte_offset>:<length> | hex [| <datagram_index>]
    """
    body = raw_filter[4:].strip()
    parts = [p.strip() for p in body.split("|")]
    if len(parts) < 2:
        raise ValueError("PDO 語法錯誤，格式: pdo: 過濾條件 | Byte位置[.Bit位置] | 資料格式 [| Datagram序號]")

    base_filter = parts[0] or "ecat"
    offset_spec = parts[1]
    dtype = parts[2].lower() if len(parts) >= 3 and parts[2] else "uint16"
    dg_index = int(parts[3]) if len(parts) >= 4 and parts[3] else 0

    bit_idx = None
    length = None

    if "." in offset_spec:
        b_str, bit_str = offset_spec.split(".", 1)
        byte_offset = int(b_str, 0)
        bit_idx = int(bit_str, 0)
        if not (0 <= bit_idx <= 7):
            raise ValueError("Bit 索引必須在 0 到 7 之間")
        dtype = "bit"
        length = 1
    elif ":" in offset_spec:
        b_str, len_str = offset_spec.split(":", 1)
        byte_offset = int(b_str, 0)
        length = int(len_str, 0)
        if dtype not in ("hex", "bytes"):
            dtype = "hex"
    else:
        byte_offset = int(offset_spec, 0)
        if dtype not in PDO_TYPES:
            raise ValueError(f"不支援的資料格式: {dtype} (支援 bit, uint8~64, int8~64, float, double, hex)")
        length, _ = PDO_TYPES[dtype]

    if byte_offset < 0 or length <= 0:
        raise ValueError("Byte 偏移量必須 >= 0 且長度 > 0")

    return {
        "base_filter": base_filter,
        "byte_offset": byte_offset,
        "bit_idx": bit_idx,
        "length": length,
        "dtype": dtype,
        "dg_index": dg_index,
    }


def decode_ecat_value(hex_str, rule):
    datagrams = [d.strip() for d in hex_str.split(",") if d.strip()]
    dg_idx = rule["dg_index"]
    if dg_idx >= len(datagrams):
        return None

    clean_hex = datagrams[dg_idx].replace(":", "").replace(" ", "")
    try:
        raw_bytes = bytes.fromhex(clean_hex)
    except ValueError:
        return None

    start = rule["byte_offset"]
    end = start + rule["length"]
    if len(raw_bytes) < end:
        return None

    chunk = raw_bytes[start:end]
    dtype = rule["dtype"]

    if dtype in ("bit", "bool"):
        bit_idx = rule["bit_idx"] if rule["bit_idx"] is not None else 0
        val = (chunk[0] >> bit_idx) & 1
        return float(val), f"{val}"

    if dtype in ("hex", "bytes"):
        formatted = ":".join(f"{b:02x}" for b in chunk)
        num_val = float(int.from_bytes(chunk, "little"))
        return num_val, formatted

    _, fmt = PDO_TYPES[dtype]
    val = struct.unpack(fmt, chunk)[0]
    if dtype in ("float", "float32", "double", "float64"):
        return round(float(val), 6), f"{val:.4f}"
    return float(val), str(val)


def scan_ecat_pdo_channel(path, raw_filter):
    try:
        rule = parse_pdo_rule(raw_filter)
    except ValueError as exc:
        return {"filter": raw_filter, "error": str(exc), "events": [], "is_pdo": True}

    try:
        proc = subprocess.run(
            [
                TSHARK,
                "-r",
                str(path),
                "-Y",
                rule["base_filter"],
                "-T",
                "fields",
                "-e",
                "frame.time_relative",
                "-e",
                "frame.number",
                "-e",
                "ecat.data",
                "-E",
                "separator=\x1f",
                "-E",
                "occurrence=a",
                "-E",
                "quote=n",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return {"filter": raw_filter, "error": f"找不到 {TSHARK}，請確認已安裝 Wireshark", "events": [], "is_pdo": True}

    if proc.returncode != 0 and not proc.stdout.strip():
        message = ""
        for line in proc.stderr.splitlines():
            line = line.strip()
            if line.startswith("tshark:"):
                message = line[len("tshark:") :].strip()
                break
        if not message:
            message = proc.stderr.strip() or "過濾指令無法執行"
        if "cut short" not in message.lower():
            return {"filter": raw_filter, "error": message, "events": [], "is_pdo": True}

    events = []
    last_val = None
    last_str = None
    last_t = None
    last_n = None
    has_initialized = False

    loc_label = f"Byte[{rule['byte_offset']}]"
    if rule["bit_idx"] is not None:
        loc_label += f".Bit[{rule['bit_idx']}]"
    elif rule["length"] > 1:
        loc_label = f"Byte[{rule['byte_offset']}:{rule['byte_offset']+rule['length']-1}]"

    for line in proc.stdout.splitlines():
        parts = line.split("\x1f")
        if len(parts) < 3 or not parts[0] or not parts[2]:
            continue
        try:
            t_rel = float(parts[0])
            f_num = int(float(parts[1]))
        except ValueError:
            continue

        decoded = decode_ecat_value(parts[2], rule)
        if decoded is None:
            continue
        val, val_str = decoded

        if not has_initialized:
            has_initialized = True
            last_val = val
            last_str = val_str
            events.append(
                {
                    "t": t_rel,
                    "n": f_num,
                    "val": val,
                    "val_str": val_str,
                    "proto": f"PDO({rule['dtype']})",
                    "info": f"[初始] {loc_label} = {val_str}",
                }
            )
        elif val != last_val:
            events.append(
                {
                    "t": t_rel,
                    "n": f_num,
                    "val": val,
                    "val_str": val_str,
                    "proto": f"PDO({rule['dtype']})",
                    "info": f"{loc_label}: {last_str} -> {val_str}",
                }
            )
            last_val = val
            last_str = val_str

        last_t = t_rel
        last_n = f_num

    # 補上最後一個取樣時間點的水平延伸點，讓示波器階梯波形能完整畫到封包結尾
    if has_initialized and last_t is not None and (not events or events[-1]["t"] < last_t):
        events.append(
            {
                "t": last_t,
                "n": last_n,
                "val": last_val,
                "val_str": last_str,
                "proto": f"PDO({rule['dtype']})",
                "info": f"[維持] {loc_label} = {last_str}",
                "is_hold": True,
            }
        )

    return {
        "filter": raw_filter,
        "error": None,
        "events": events,
        "is_pdo": True,
        "dtype": rule["dtype"],
        "loc_label": loc_label,
    }


def scan_channel(path, display_filter):
    display_filter = display_filter.replace("\x00", "").strip()
    if not display_filter:
        return {"filter": "", "error": None, "events": []}
    if len(display_filter) > 500:
        return {"filter": display_filter, "error": "過濾指令過長", "events": []}

    if display_filter.lower().startswith("pdo:"):
        return scan_ecat_pdo_channel(path, display_filter)

    try:
        proc = subprocess.run(
            [
                TSHARK,
                "-r",
                str(path),
                "-Y",
                display_filter,
                "-T",
                "fields",
                "-e",
                "frame.time_relative",
                "-e",
                "frame.number",
                "-e",
                "_ws.col.Protocol",
                "-e",
                "_ws.col.Info",
                "-E",
                "separator=\x1f",
                "-E",
                "occurrence=f",
                "-E",
                "quote=n",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError:
        return {"filter": display_filter, "error": f"找不到 {TSHARK}，請確認已安裝 Wireshark", "events": []}
    if proc.returncode != 0 and not proc.stdout.strip():
        message = ""
        for line in proc.stderr.splitlines():
            line = line.strip()
            if line.startswith("tshark:"):
                message = line[len("tshark:") :].strip()
                break
        if not message:
            message = proc.stderr.strip() or "過濾指令無法執行"
        if "cut short" not in message.lower():
            return {"filter": display_filter, "error": message, "events": []}

    events = []
    for line in proc.stdout.splitlines():
        parts = line.split("\x1f")
        if len(parts) < 2 or not parts[0]:
            continue
        try:
            events.append(
                {
                    "t": float(parts[0]),
                    "n": int(float(parts[1])),
                    "proto": parts[2] if len(parts) > 2 else "",
                    "info": (parts[3] if len(parts) > 3 else "")[:180],
                }
            )
        except ValueError:
            continue
    return {"filter": display_filter, "error": None, "events": events}


def scan_all(path, filters):
    padded = list(filters[:CHANNEL_COUNT])
    padded.extend([""] * (CHANNEL_COUNT - len(padded)))
    with ThreadPoolExecutor(max_workers=8) as pool:
        channels = list(pool.map(lambda item: scan_channel(path, item), padded))

    max_t = 0.0
    total_events = 0
    for index, channel in enumerate(channels):
        channel["index"] = index
        evs = channel["events"]
        total_events += len(evs)
        if evs and evs[-1]["t"] > max_t:
            max_t = evs[-1]["t"]

    meta = capture_meta(path, fallback_duration=max_t if max_t > 0 else 1.0)
    if meta["packets"] == 0 and total_events > 0:
        meta["packets"] = total_events
    meta["channels"] = channels
    return meta


# --- 前端注入：即時監控面板 + PDO 規則產生器 + HTML5 Canvas 數值階梯波形渲染器 ---
LIVE_UI_INJECTION = """
<div id="live-capture-bar" style="background:#1e293b;color:#f8fafc;padding:10px 16px;font-family:system-ui,sans-serif;border-bottom:1px solid #334155;font-size:13px;">
  <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
    <strong style="color:#38bdf8;">⚡ 即時抓包監控：</strong>
    <select id="live-iface" style="background:#0f172a;color:#f8fafc;border:1px solid #475569;padding:4px 8px;border-radius:4px;max-width:300px;">
      <option value="">載入網卡中...</option>
    </select>
    <button id="live-toggle-btn" style="background:#10b981;color:#fff;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-weight:bold;">開始即時監控</button>
    <span id="live-status" style="color:#94a3b8;">待機中</span>
    <button id="pdo-helper-toggle" style="margin-left:auto;background:#0284c7;color:#fff;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-weight:bold;">📈 EtherCAT PDO 數值波形產生器</button>
  </div>

  <div id="pdo-helper-panel" style="display:none;margin-top:10px;padding-top:10px;border-top:1px dashed #475569;align-items:center;gap:8px;flex-wrap:wrap;">
    <span style="color:#fbbf24;font-weight:bold;">PDO 波形設定：</span>
    <input id="pdo-base" type="text" value="ecat" placeholder="基礎過濾 (如 ecat.ado == 0x1000)" style="background:#0f172a;color:#f8fafc;border:1px solid #475569;padding:4px 8px;border-radius:4px;width:190px;">
    <label>Byte 起始:<input id="pdo-byte" type="number" min="0" value="0" style="background:#0f172a;color:#f8fafc;border:1px solid #475569;padding:4px;border-radius:4px;width:55px;margin-left:4px;"></label>
    <label>資料格式:
      <select id="pdo-dtype" style="background:#0f172a;color:#f8fafc;border:1px solid #475569;padding:4px;border-radius:4px;margin-left:4px;">
        <option value="bit">bit (單一 Bit 0/1)</option>
        <option value="uint8">uint8 (1 Byte 無號)</option>
        <option value="int8">int8 (1 Byte 有號)</option>
        <option value="uint16" selected>uint16 (2 Bytes LE)</option>
        <option value="int16">int16 (2 Bytes LE)</option>
        <option value="uint32">uint32 (4 Bytes LE)</option>
        <option value="int32">int32 (4 Bytes LE)</option>
        <option value="float">float (4 Bytes LE)</option>
        <option value="double">double (8 Bytes LE)</option>
        <option value="hex">hex (自訂 Byte 長度)</option>
      </select>
    </label>
    <label id="pdo-bit-wrap" style="display:none;">Bit(0-7):<input id="pdo-bit" type="number" min="0" max="7" value="0" style="background:#0f172a;color:#f8fafc;border:1px solid #475569;padding:4px;border-radius:4px;width:45px;margin-left:4px;"></label>
    <label id="pdo-len-wrap" style="display:none;">長度:<input id="pdo-len" type="number" min="1" value="2" style="background:#0f172a;color:#f8fafc;border:1px solid #475569;padding:4px;border-radius:4px;width:45px;margin-left:4px;"></label>
    <label>Datagram序號:<input id="pdo-dg" type="number" min="0" value="0" style="background:#0f172a;color:#f8fafc;border:1px solid #475569;padding:4px;border-radius:4px;width:45px;margin-left:4px;" title="單一Frame有多個Datagram時指定序號(從0起算)"></label>
    <button id="pdo-copy-btn" style="background:#10b981;color:#fff;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-weight:bold;">填入空白頻道並掃描</button>
    <span id="pdo-preview" style="color:#38bdf8;font-family:monospace;"></span>
  </div>
</div>

<!-- 浮動數值波形檢視視窗：自動為所有 PDO 頻道繪製真實 Y 軸數值階梯曲線 -->
<div id="pdo-scope-dock" style="display:none;background:#0b1120;color:#e2e8f0;padding:12px 16px;border-bottom:2px solid #0284c7;font-family:system-ui,sans-serif;">
  <div style="display:flex;align-items:center;gap:8px;justify-content:space-between;margin-bottom:8px;flex-wrap:wrap;">
    <strong style="color:#38bdf8;font-size:14px;">📊 EtherCAT PDO 數值波形示波器 (Y軸：實際工程數值 / X軸：相對時間)</strong>
    <div style="display:flex;align-items:center;gap:6px;">
      <button id="pdo-full-btn" type="button" style="background:#1e293b;color:#e2e8f0;border:1px solid #475569;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px;">全程</button>
      <button id="pdo-measure-btn" type="button" title="開啟後拖曳建立時間測量區塊（平時亦可按住 Shift+拖曳）" style="background:#1e293b;color:#e2e8f0;border:1px solid #475569;padding:3px 10px;border-radius:4px;cursor:pointer;font-size:12px;">📏 測量</button>
      <button id="pdo-clear-measures" type="button" disabled style="background:#1e293b;color:#94a3b8;border:1px solid #334155;padding:3px 10px;border-radius:4px;cursor:not-allowed;font-size:12px;">清除測量</button>
    </div>
    <span id="pdo-cursor-readout" style="font-family:monospace;font-size:13px;color:#fbbf24;">滾輪縮放時間，拖曳平移，雙擊回到全程；開啟「測量」或 Shift+拖曳新增多組測量，滑鼠移至測量區塊顯示統計，右鍵或點 × 刪除</span>
  </div>
  <div id="pdo-axis-row" style="display:flex;align-items:stretch;background:#0f172a;border:1px solid #1e293b;border-radius:6px 6px 0 0;margin-bottom:6px;overflow:hidden;height:26px;">
    <div style="width:215px;flex-shrink:0;padding:0 10px;border-right:1px solid #1e293b;display:flex;align-items:center;font-size:11px;color:#94a3b8;background:#131c31;">時間軸</div>
    <div id="pdo-axis-wrap" style="flex:1;position:relative;cursor:ew-resize;">
      <canvas id="pdo-axis" style="width:100%;height:26px;display:block;"></canvas>
    </div>
  </div>
  <div id="pdo-waveforms-container" style="display:flex;flex-direction:column;gap:8px;max-height:460px;overflow-y:auto;"></div>
</div>
<div id="pdo-measure-tooltip" style="position:fixed;z-index:9999;pointer-events:none;display:none;background:rgba(15,23,42,0.96);border:1px solid #38bdf8;border-radius:6px;padding:8px 10px;color:#e2e8f0;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;box-shadow:0 8px 24px rgba(0,0,0,0.45);max-width:440px;"></div>

<script>
(function() {
  const ifaceSelect = document.getElementById('live-iface');
  const toggleBtn = document.getElementById('live-toggle-btn');
  const statusSpan = document.getElementById('live-status');
  const helperToggle = document.getElementById('pdo-helper-toggle');
  const helperPanel = document.getElementById('pdo-helper-panel');
  const pdoBase = document.getElementById('pdo-base');
  const pdoByte = document.getElementById('pdo-byte');
  const pdoDtype = document.getElementById('pdo-dtype');
  const pdoBitWrap = document.getElementById('pdo-bit-wrap');
  const pdoBit = document.getElementById('pdo-bit');
  const pdoLenWrap = document.getElementById('pdo-len-wrap');
  const pdoLen = document.getElementById('pdo-len');
  const pdoDg = document.getElementById('pdo-dg');
  const pdoCopyBtn = document.getElementById('pdo-copy-btn');
  const pdoPreview = document.getElementById('pdo-preview');

  const scopeDock = document.getElementById('pdo-scope-dock');
  const pdoFullBtn = document.getElementById('pdo-full-btn');
  const pdoMeasureBtn = document.getElementById('pdo-measure-btn');
  const pdoClearMeasuresBtn = document.getElementById('pdo-clear-measures');
  const pdoAxisWrap = document.getElementById('pdo-axis-wrap');
  const pdoAxisCanvas = document.getElementById('pdo-axis');
  const waveformsContainer = document.getElementById('pdo-waveforms-container');
  const cursorReadout = document.getElementById('pdo-cursor-readout');
  const pdoMeasureTooltip = document.getElementById('pdo-measure-tooltip');

  let pollTimer = null;
  let isLive = false;
  let latestScanData = null;

  const PDO_DEFAULT_HINT = '滾輪縮放時間，拖曳平移，雙擊回到全程；開啟「測量」或 Shift+拖曳新增多組測量，滑鼠移至測量區塊顯示統計，右鍵或點 × 刪除';
  const PDO_MEASURE_COLORS = ['#38bdf8', '#f59e0b', '#10b981', '#ec4899', '#a855f7', '#fb923c'];
  const PDO_PAD = { left: 8, right: 12 };

  let pdoDuration = 1;
  let pdoFile = '';
  let pdoView = { t0: 0, t1: 1 };
  let pdoCursorT = null;
  let pdoMeasureMode = false;
  let pdoMeasures = [];
  let pdoNextMeasureId = 1;
  let pdoDrag = null;
  let pdoMeasureDrag = null;
  let pdoHoveredMeasure = null;
  let pdoRowModels = [];

  const CHANNEL_COLORS = [
    '#38bdf8', '#4ade80', '#facc15', '#f472b6', '#a78bfa',
    '#fb923c', '#2dd4bf', '#e879f9', '#60a5fa', '#a3e635'
  ];

  // 攔截 /api/scan 回應，取得帶有真實數值 (val) 的 PDO 事件並繪製 Y 軸數值波形
  const origFetch = window.fetch;
  window.fetch = async function(...args) {
    const response = await origFetch.apply(this, args);
    const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
    if (url.includes('/api/scan')) {
      try {
        const cloned = response.clone();
        const data = await cloned.json();
        if (data && Array.isArray(data.channels)) {
          latestScanData = data;
          renderPdoWaveforms(data);
        }
      } catch (e) {}
    }
    return response;
  };

  window.addEventListener('resize', () => {
    if (pdoRowModels.length > 0) drawPdoAll();
  });

  function formatAxisNum(num, dtype) {
    if (dtype === 'bit' || dtype === 'bool') return num >= 0.5 ? '1' : '0';
    if (Number.isInteger(num)) return String(num);
    return num.toFixed(2);
  }

  function pdoFmtTime(t) {
    const sign = t < 0 ? '-' : '';
    t = Math.abs(t);
    if (t < 0.001) return sign + (t * 1e6).toFixed(0) + ' µs';
    if (t < 1) return sign + (t * 1000).toFixed(t < 0.01 ? 2 : 1) + ' ms';
    return sign + t.toFixed(4) + ' s';
  }

  function pdoFmtFreq(dt) {
    if (!(dt > 0)) return '-';
    const hz = 1 / dt;
    if (hz >= 1e6) return (hz / 1e6).toFixed(3) + ' MHz';
    if (hz >= 1e3) return (hz / 1e3).toFixed(2) + ' kHz';
    return hz.toFixed(hz < 10 ? 2 : 1) + ' Hz';
  }

  function pdoNiceStep(span) {
    const target = span / 8;
    if (!(target > 0)) return span || 1;
    const pow = Math.pow(10, Math.floor(Math.log10(target)));
    for (const mult of [1, 2, 5, 10]) {
      if (mult * pow >= target * 0.75) return mult * pow;
    }
    return pow * 10;
  }

  function pdoTimeToX(t, w) {
    const plotW = Math.max(1, w - PDO_PAD.left - PDO_PAD.right);
    const span = Math.max(1e-12, pdoView.t1 - pdoView.t0);
    return PDO_PAD.left + ((t - pdoView.t0) / span) * plotW;
  }

  function pdoXToTime(x, w) {
    const plotW = Math.max(1, w - PDO_PAD.left - PDO_PAD.right);
    const ratio = (x - PDO_PAD.left) / plotW;
    return pdoView.t0 + ratio * (pdoView.t1 - pdoView.t0);
  }

  function updatePdoMeasureButtons() {
    if (pdoMeasureMode) {
      pdoMeasureBtn.style.background = '#1d4ed8';
      pdoMeasureBtn.style.borderColor = '#3b82f6';
      pdoMeasureBtn.style.color = '#ffffff';
    } else {
      pdoMeasureBtn.style.background = '#1e293b';
      pdoMeasureBtn.style.borderColor = '#475569';
      pdoMeasureBtn.style.color = '#e2e8f0';
    }
    pdoClearMeasuresBtn.textContent = pdoMeasures.length ? `清除測量 (${pdoMeasures.length})` : '清除測量';
    pdoClearMeasuresBtn.disabled = pdoMeasures.length === 0;
    pdoClearMeasuresBtn.style.color = pdoMeasures.length ? '#e2e8f0' : '#94a3b8';
    pdoClearMeasuresBtn.style.borderColor = pdoMeasures.length ? '#475569' : '#334155';
    pdoClearMeasuresBtn.style.cursor = pdoMeasures.length ? 'pointer' : 'not-allowed';
    pdoRowModels.forEach(row => {
      row.canvasWrap.style.cursor = pdoMeasureMode ? 'col-resize' : 'crosshair';
    });
  }

  function pdoResetView() {
    pdoView = { t0: 0, t1: Math.max(pdoDuration || 1e-6, 1e-6) };
    drawPdoAll();
  }

  function pdoZoomAt(x, w, factor) {
    const focus = pdoXToTime(x, w);
    const span = (pdoView.t1 - pdoView.t0) * factor;
    const minSpan = 20e-6;
    const full = Math.max(pdoDuration || 1e-6, 1e-6);
    const next = Math.min(full, Math.max(minSpan, span));
    const ratio = (focus - pdoView.t0) / Math.max(1e-12, pdoView.t1 - pdoView.t0);
    let t0 = focus - ratio * next;
    let t1 = t0 + next;
    if (t0 < 0) { t1 -= t0; t0 = 0; }
    if (t1 > full) { t0 -= t1 - full; t1 = full; }
    if (t0 < 0) t0 = 0;
    pdoView = { t0, t1 };
    drawPdoAll();
  }

  function pdoPillRect(m, w) {
    const x0 = pdoTimeToX(m.t0, w);
    const x1 = pdoTimeToX(m.t1, w);
    const x = Math.max(0, Math.min(w - 52, Math.min(x0, x1) + 2));
    return { x, y: 2, w: 48, h: 16, closeX0: x + 32, closeX1: x + 48, showClose: true };
  }

  function findPdoMeasureAt(x, y, w) {
    let best = null;
    let bestSpan = Infinity;
    let hitClose = false;
    for (const m of pdoMeasures) {
      const pill = pdoPillRect(m, w);
      const onPill = x >= pill.x && x <= pill.x + pill.w && y >= pill.y && y <= pill.y + pill.h;
      const onClose = onPill && x >= pill.closeX0 && x <= pill.closeX1;
      const x0 = Math.min(pdoTimeToX(m.t0, w), pdoTimeToX(m.t1, w));
      const x1 = Math.max(pdoTimeToX(m.t0, w), pdoTimeToX(m.t1, w));
      const insideBand = (x >= x0 - 2 && x <= x1 + 2) || onPill;
      if (!insideBand) continue;
      const span = Math.abs(m.t1 - m.t0);
      if (onClose && !hitClose) {
        best = m;
        bestSpan = span;
        hitClose = true;
      } else if (onClose === hitClose && span < bestSpan) {
        best = m;
        bestSpan = span;
      }
    }
    if (!best) return null;
    return { measure: best, isClose: hitClose };
  }

  function computePdoMeasureStats(ch, m) {
    const events = ch.events || [];
    const t0 = m.t0;
    const t1 = m.t1;
    const dt = Math.max(0, t1 - t0);
    const valueAt = (t) => {
      let res = null;
      for (let i = 0; i < events.length; i++) {
        if (events[i].t <= t) res = events[i];
        else break;
      }
      return res;
    };

    const startEv = valueAt(t0);
    const endEv = valueAt(t1);
    const startVal = startEv ? startEv.val : null;
    const endVal = endEv ? endEv.val : null;
    const deltaVal = (startVal !== null && endVal !== null) ? (endVal - startVal) : null;

    let idx = -1;
    for (let i = 0; i < events.length; i++) {
      if (events[i].t <= t0) idx = i;
      else break;
    }

    let minVal = Infinity;
    let maxVal = -Infinity;
    let area = 0;
    let coveredT = 0;
    let highTime = 0;
    let transitions = 0;

    let curT = t0;
    let curVal = idx >= 0 ? events[idx].val : null;
    if (curVal !== null) {
      minVal = Math.min(minVal, curVal);
      maxVal = Math.max(maxVal, curVal);
    }

    for (let j = idx + 1; j < events.length; j++) {
      if (events[j].t > t1) break;
      const segEnd = events[j].t;
      if (curVal !== null && segEnd > curT) {
        const segDt = segEnd - curT;
        area += curVal * segDt;
        coveredT += segDt;
        if (curVal >= 0.5) highTime += segDt;
      }
      if (!events[j].is_hold && events[j].t > t0) {
        transitions++;
      }
      curT = segEnd;
      curVal = events[j].val;
      minVal = Math.min(minVal, curVal);
      maxVal = Math.max(maxVal, curVal);
    }
    if (curVal !== null && t1 > curT) {
      const segDt = t1 - curT;
      area += curVal * segDt;
      coveredT += segDt;
      if (curVal >= 0.5) highTime += segDt;
    }

    const avgVal = coveredT > 0 ? (area / coveredT) : startVal;
    if (minVal === Infinity) {
      minVal = null;
      maxVal = null;
    }
    const isBit = ch.dtype === 'bit' || ch.dtype === 'bool';
    const dutyPct = (isBit && dt > 0) ? (highTime / dt) * 100 : null;
    return {
      dt,
      freq: pdoFmtFreq(dt),
      startEv,
      endEv,
      startVal,
      endVal,
      deltaVal,
      minVal,
      maxVal,
      avgVal,
      transitions,
      isBit,
      highTime,
      dutyPct,
    };
  }

  function fmtStatVal(v, dtype) {
    if (v === null || v === undefined || Number.isNaN(v)) return '-';
    if (dtype === 'bit' || dtype === 'bool') return v >= 0.5 ? '1' : '0';
    if (Number.isInteger(v)) return String(v);
    return v.toFixed(4);
  }

  function hidePdoMeasureTooltip() {
    pdoMeasureTooltip.style.display = 'none';
  }

  function showPdoMeasureTooltip(m, ch, clientX, clientY) {
    const s = computePdoMeasureStats(ch, m);
    const chColor = CHANNEL_COLORS[ch.index % CHANNEL_COLORS.length];
    let valRows = '';
    if (s.startVal === null && s.minVal === null) {
      valRows = '<div style="color:#94a3b8;">此時間區間內尚未有取樣資料</div>';
    } else {
      const deltaStr = s.deltaVal !== null ? (s.deltaVal > 0 ? '+' : '') + fmtStatVal(s.deltaVal, ch.dtype) : '-';
      const avgStr = s.avgVal !== null ? (s.isBit ? s.avgVal.toFixed(3) : s.avgVal.toFixed(3)) : '-';
      valRows =
        `<div>起始值: ${s.startEv ? s.startEv.val_str : '-'}  |  結束值: ${s.endEv ? s.endEv.val_str : '-'}  |  ΔVal: ${deltaStr}</div>` +
        `<div>Min: ${fmtStatVal(s.minVal, ch.dtype)}  |  Max: ${fmtStatVal(s.maxVal, ch.dtype)}  |  平均: ${avgStr}</div>` +
        `<div>變化次數: ${s.transitions} 次` +
        (s.isBit && s.dutyPct !== null ? `  |  高電位: ${pdoFmtTime(s.highTime)} (${s.dutyPct.toFixed(1)}%)` : '') +
        '</div>';
    }
    pdoMeasureTooltip.innerHTML =
      `<div style="font-weight:700;color:${m.color};margin-bottom:4px;">測量 M${m.id} <span style="color:#94a3b8;font-weight:400;">(右鍵或點 × 刪除)</span></div>` +
      `<div>T1: ${pdoFmtTime(m.t0)}  |  T2: ${pdoFmtTime(m.t1)}</div>` +
      `<div style="color:#f8fafc;font-weight:600;margin-bottom:4px;">ΔT: ${pdoFmtTime(s.dt)}  |  1/ΔT: ${s.freq}</div>` +
      `<div style="color:${chColor};font-weight:600;margin-bottom:2px;">CH${ch.index + 1} · ${ch.loc_label || 'PDO'} (${ch.dtype})</div>` +
      valRows;
    pdoMeasureTooltip.style.display = 'block';
    const rect = pdoMeasureTooltip.getBoundingClientRect();
    let left = clientX + 14;
    let top = clientY + 14;
    if (left + rect.width > window.innerWidth - 8) left = Math.max(8, clientX - rect.width - 14);
    if (top + rect.height > window.innerHeight - 8) top = Math.max(8, clientY - rect.height - 14);
    pdoMeasureTooltip.style.left = left + 'px';
    pdoMeasureTooltip.style.top = top + 'px';
  }

  function drawPdoAxis() {
    const rect = pdoAxisWrap.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const w = Math.max(rect.width, 300);
    const h = 26;
    const bw = Math.max(1, Math.round(w * dpr));
    const bh = Math.max(1, Math.round(h * dpr));
    if (pdoAxisCanvas.width !== bw || pdoAxisCanvas.height !== bh) {
      pdoAxisCanvas.width = bw;
      pdoAxisCanvas.height = bh;
    }
    const ctx = pdoAxisCanvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    ctx.fillStyle = '#0f172a';
    ctx.fillRect(0, 0, w, h);

    for (const m of pdoMeasures) {
      if (m.t1 < pdoView.t0 || m.t0 > pdoView.t1) continue;
      const x0 = Math.max(0, pdoTimeToX(m.t0, w));
      const x1 = Math.min(w, pdoTimeToX(m.t1, w));
      ctx.fillStyle = m.color;
      ctx.fillRect(x0, 0, Math.max(2, x1 - x0), 3);
    }

    const step = pdoNiceStep(pdoView.t1 - pdoView.t0);
    const start = Math.ceil(pdoView.t0 / step) * step;
    ctx.font = '11px ui-monospace, SFMono-Regular, Menlo, monospace';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'middle';
    for (let t = start; t <= pdoView.t1 + step * 0.01; t += step) {
      const x = pdoTimeToX(t, w);
      if (x < 0 || x > w) continue;
      ctx.strokeStyle = '#334155';
      ctx.beginPath();
      ctx.moveTo(x, h - 5);
      ctx.lineTo(x, h);
      ctx.stroke();
      ctx.fillStyle = '#94a3b8';
      ctx.fillText(pdoFmtTime(t), x, h / 2 + 1);
    }
  }

  function drawPdoRow(row) {
    const { ch, color, canvas, canvasWrap, minVal, maxVal } = row;
    const events = ch.events;
    const rect = canvasWrap.getBoundingClientRect();
    const dpr = window.devicePixelRatio || 1;
    const w = Math.max(rect.width, 300);
    const h = Math.max(rect.height, 104);
    const bw = Math.max(1, Math.round(w * dpr));
    const bh = Math.max(1, Math.round(h * dpr));
    if (canvas.width !== bw || canvas.height !== bh) {
      canvas.width = bw;
      canvas.height = bh;
    }
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);

    const padTop = 16;
    const padBottom = 16;
    const plotH = h - padTop - padBottom;
    const valSpan = Math.max(maxVal - minVal, 1e-9);
    const valToY = (v) => padTop + plotH - ((v - minVal) / valSpan) * plotH;

    // 垂直時間參考網格線
    const step = pdoNiceStep(pdoView.t1 - pdoView.t0);
    const startT = Math.ceil(pdoView.t0 / step) * step;
    ctx.strokeStyle = '#182235';
    ctx.lineWidth = 1;
    for (let t = startT; t <= pdoView.t1 + step * 0.01; t += step) {
      const gx = pdoTimeToX(t, w);
      if (gx < 0 || gx > w) continue;
      ctx.beginPath();
      ctx.moveTo(gx, 0);
      ctx.lineTo(gx, h);
      ctx.stroke();
    }

    // 背景水平參考網格線 (Max / Mid / Min)
    ctx.strokeStyle = '#1e293b';
    ctx.lineWidth = 1;
    [0, 0.5, 1].forEach(ratio => {
      const gy = padTop + plotH * ratio;
      ctx.beginPath();
      ctx.moveTo(0, gy);
      ctx.lineTo(w, gy);
      ctx.stroke();
    });

    // 繪製 Y 軸刻度文字
    ctx.fillStyle = '#64748b';
    ctx.font = '10px monospace';
    ctx.textAlign = 'left';
    ctx.textBaseline = 'alphabetic';
    ctx.fillText(formatAxisNum(maxVal, ch.dtype), 4, padTop - 4);
    ctx.fillText(formatAxisNum(minVal, ch.dtype), 4, h - 4);

    // 繪製階梯波形 (Step Waveform，支援縮放/平移視窗裁剪)
    if (events.length > 0 && events[0].t <= pdoView.t1) {
      let startIdx = 0;
      for (let i = 0; i < events.length; i++) {
        if (events[i].t <= pdoView.t0) startIdx = i;
        else break;
      }

      ctx.strokeStyle = color;
      ctx.lineWidth = 2;
      ctx.beginPath();

      let prevX = pdoTimeToX(Math.max(events[startIdx].t, pdoView.t0), w);
      let prevY = valToY(events[startIdx].val);
      ctx.moveTo(prevX, prevY);

      for (let i = startIdx + 1; i < events.length; i++) {
        if (events[i].t > pdoView.t1) break;
        const currX = pdoTimeToX(events[i].t, w);
        const currY = valToY(events[i].val);
        ctx.lineTo(currX, prevY);
        ctx.lineTo(currX, currY);
        prevX = currX;
        prevY = currY;
      }
      ctx.lineTo(pdoTimeToX(pdoView.t1, w), prevY);
      ctx.stroke();

      // 在每次數值變化的轉折點畫上小圓點並標註數值
      ctx.fillStyle = color;
      let lastLabelX = -999;
      for (let i = 0; i < events.length; i++) {
        if (events[i].is_hold) continue;
        if (events[i].t < pdoView.t0 || events[i].t > pdoView.t1) continue;
        const px = pdoTimeToX(events[i].t, w);
        const py = valToY(events[i].val);
        ctx.beginPath();
        ctx.arc(px, py, 3, 0, Math.PI * 2);
        ctx.fill();

        if (px - lastLabelX > 48) {
          ctx.fillStyle = '#f8fafc';
          ctx.font = '11px monospace';
          const textY = py < h / 2 ? py + 13 : py - 5;
          ctx.fillText(events[i].val_str, px + 4, textY);
          ctx.fillStyle = color;
          lastLabelX = px;
        }
      }
    }

    // 繪製測量區塊（僅標記標籤，統計數值於滑鼠懸停時才顯示）
    const drawBand = (t0, t1, bandColor, label, isHovered, pillRect) => {
      if (t1 < pdoView.t0 || t0 > pdoView.t1) return;
      const rawX0 = pdoTimeToX(t0, w);
      const rawX1 = pdoTimeToX(t1, w);
      const left = Math.max(0, Math.min(rawX0, rawX1));
      const right = Math.min(w, Math.max(rawX0, rawX1));
      const bandW = Math.max(1, right - left);

      ctx.save();
      ctx.fillStyle = bandColor;
      ctx.globalAlpha = isHovered ? 0.24 : 0.14;
      ctx.fillRect(left, 0, bandW, h);

      ctx.globalAlpha = isHovered ? 0.95 : 0.8;
      ctx.strokeStyle = bandColor;
      ctx.lineWidth = isHovered ? 2 : 1.2;
      if (rawX0 >= 0 && rawX0 <= w) {
        ctx.beginPath();
        ctx.moveTo(rawX0 + 0.5, 0);
        ctx.lineTo(rawX0 + 0.5, h);
        ctx.stroke();
      }
      if (rawX1 >= 0 && rawX1 <= w) {
        ctx.beginPath();
        ctx.moveTo(rawX1 + 0.5, 0);
        ctx.lineTo(rawX1 + 0.5, h);
        ctx.stroke();
      }

      if (pillRect) {
        ctx.globalAlpha = 0.92;
        ctx.fillStyle = '#0f172a';
        ctx.fillRect(pillRect.x, pillRect.y, pillRect.w, pillRect.h);
        ctx.strokeStyle = bandColor;
        ctx.lineWidth = 1;
        ctx.strokeRect(pillRect.x + 0.5, pillRect.y + 0.5, pillRect.w - 1, pillRect.h - 1);
        ctx.fillStyle = bandColor;
        ctx.font = '11px ui-monospace, SFMono-Regular, Menlo, monospace';
        ctx.textAlign = 'left';
        ctx.textBaseline = 'middle';
        ctx.fillText(label, pillRect.x + 5, pillRect.y + pillRect.h / 2 + 0.5);
        if (pillRect.showClose) {
          ctx.fillStyle = '#94a3b8';
          ctx.fillText('×', pillRect.closeX0 + 3, pillRect.y + pillRect.h / 2 + 0.5);
        }
      }
      ctx.restore();
    };

    for (const m of pdoMeasures) {
      const isHovered = Boolean(pdoHoveredMeasure && pdoHoveredMeasure.id === m.id);
      drawBand(m.t0, m.t1, m.color, `M${m.id}`, isHovered, pdoPillRect(m, w));
    }
    if (pdoMeasureDrag) {
      const pt0 = Math.min(pdoMeasureDrag.startT, pdoMeasureDrag.currT);
      const pt1 = Math.max(pdoMeasureDrag.startT, pdoMeasureDrag.currT);
      const px = Math.max(0, Math.min(w - 30, pdoTimeToX(pt0, w) + 2));
      drawBand(pt0, pt1, '#38bdf8', 'M?', true, { x: px, y: 2, w: 28, h: 16, showClose: false });
    }

    // 同步垂直游標線
    if (pdoCursorT != null && pdoCursorT >= pdoView.t0 && pdoCursorT <= pdoView.t1) {
      const cx = pdoTimeToX(pdoCursorT, w);
      ctx.save();
      ctx.strokeStyle = 'rgba(255,255,255,0.45)';
      ctx.setLineDash([3, 3]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(cx, 0);
      ctx.lineTo(cx, h);
      ctx.stroke();
      ctx.restore();
    }
  }

  function drawPdoAll() {
    if (pdoRowModels.length === 0) return;
    drawPdoAxis();
    pdoRowModels.forEach(drawPdoRow);
  }

  function renderPdoWaveforms(data) {
    const pdoChannels = data.channels.filter(ch => ch.is_pdo && !ch.error && ch.events && ch.events.length > 0);
    if (pdoChannels.length === 0) {
      scopeDock.style.display = 'none';
      pdoRowModels = [];
      hidePdoMeasureTooltip();
      return;
    }

    scopeDock.style.display = 'block';
    waveformsContainer.innerHTML = '';
    const totalDuration = Math.max(data.duration || 1e-6, 1e-6);
    const nextFile = data.file || '';
    if (nextFile !== pdoFile) {
      pdoFile = nextFile;
      pdoDuration = totalDuration;
      pdoView = { t0: 0, t1: totalDuration };
      pdoMeasures = [];
      pdoNextMeasureId = 1;
      pdoHoveredMeasure = null;
      hidePdoMeasureTooltip();
    } else {
      const wasFull = pdoView.t0 <= 1e-9 && Math.abs(pdoView.t1 - pdoDuration) < 1e-6;
      pdoDuration = totalDuration;
      if (wasFull) {
        pdoView = { t0: 0, t1: totalDuration };
      } else {
        pdoView.t1 = Math.min(pdoView.t1, totalDuration);
        pdoView.t0 = Math.min(pdoView.t0, Math.max(0, pdoView.t1 - 20e-6));
      }
    }

    pdoRowModels = [];

    pdoChannels.forEach((ch) => {
      const color = CHANNEL_COLORS[ch.index % CHANNEL_COLORS.length];
      const events = ch.events;
      const vals = events.map(e => e.val);
      let minVal = Math.min(...vals);
      let maxVal = Math.max(...vals);

      if (ch.dtype === 'bit' || ch.dtype === 'bool') {
        minVal = 0;
        maxVal = 1;
      } else if (minVal === maxVal) {
        minVal = minVal - 1;
        maxVal = maxVal + 1;
      }

      const row = document.createElement('div');
      row.style.cssText = 'display:flex;align-items:stretch;background:#0f172a;border:1px solid #1e293b;border-radius:6px;overflow:hidden;height:104px;';

      // 左側資訊與 Y 軸最大/最小值標籤
      const sidebar = document.createElement('div');
      sidebar.style.cssText = 'width:215px;flex-shrink:0;padding:6px 10px;border-right:1px solid #1e293b;display:flex;flex-direction:column;justify-content:space-between;background:#131c31;';
      const latestEv = events[events.length - 1];
      sidebar.innerHTML = `
        <div style="display:flex;align-items:center;justify-content:space-between;">
          <span style="font-weight:bold;color:${color};font-size:12px;">CH${ch.index + 1} · ${ch.loc_label || 'PDO'}</span>
          <span style="font-size:11px;color:#94a3b8;background:#1e293b;padding:1px 5px;border-radius:3px;">${ch.dtype}</span>
        </div>
        <div style="font-family:monospace;font-size:14px;font-weight:bold;color:#f8fafc;">
          目前: ${latestEv ? latestEv.val_str : '-'}
        </div>
        <div style="display:flex;justify-content:space-between;font-family:monospace;font-size:11px;color:#94a3b8;">
          <span>Min: ${formatAxisNum(minVal, ch.dtype)}</span>
          <span>Max: ${formatAxisNum(maxVal, ch.dtype)}</span>
        </div>
      `;

      // 右側 Canvas 階梯波形區
      const canvasWrap = document.createElement('div');
      canvasWrap.style.cssText = 'flex:1;position:relative;cursor:crosshair;';
      const canvas = document.createElement('canvas');
      canvas.style.cssText = 'width:100%;height:100%;display:block;';
      canvasWrap.appendChild(canvas);

      row.appendChild(sidebar);
      row.appendChild(canvasWrap);
      waveformsContainer.appendChild(row);

      const rowModel = { ch, color, canvas, canvasWrap, minVal, maxVal };
      pdoRowModels.push(rowModel);

      canvasWrap.addEventListener('wheel', (e) => {
        e.preventDefault();
        const cRect = canvasWrap.getBoundingClientRect();
        const factor = e.deltaY > 0 ? 1.18 : 1 / 1.18;
        pdoZoomAt(e.clientX - cRect.left, Math.max(cRect.width, 1), factor);
      }, { passive: false });

      canvasWrap.addEventListener('dblclick', pdoResetView);

      canvasWrap.addEventListener('pointerdown', (e) => {
        if (e.button !== 0) return;
        const cRect = canvasWrap.getBoundingClientRect();
        const w = Math.max(cRect.width, 1);
        const x = e.clientX - cRect.left;
        const y = e.clientY - cRect.top;
        const hit = findPdoMeasureAt(x, y, w);
        if (hit && hit.isClose) {
          pdoMeasures = pdoMeasures.filter(m => m.id !== hit.measure.id);
          if (pdoHoveredMeasure && pdoHoveredMeasure.id === hit.measure.id) pdoHoveredMeasure = null;
          hidePdoMeasureTooltip();
          updatePdoMeasureButtons();
          drawPdoAll();
          return;
        }
        canvasWrap.setPointerCapture(e.pointerId);
        hidePdoMeasureTooltip();
        if (pdoMeasureMode || e.shiftKey) {
          const t = Math.min(pdoView.t1, Math.max(pdoView.t0, pdoXToTime(x, w)));
          pdoMeasureDrag = { startX: x, startT: t, currT: t };
          drawPdoAll();
        } else {
          pdoDrag = { x: e.clientX, t0: pdoView.t0, t1: pdoView.t1, w };
        }
      });

      canvasWrap.addEventListener('pointermove', (e) => {
        const cRect = canvasWrap.getBoundingClientRect();
        const w = Math.max(cRect.width, 1);
        const x = e.clientX - cRect.left;
        const y = e.clientY - cRect.top;

        if (pdoMeasureDrag) {
          pdoMeasureDrag.currT = Math.min(pdoView.t1, Math.max(pdoView.t0, pdoXToTime(x, w)));
          pdoCursorT = pdoMeasureDrag.currT;
          drawPdoAll();
          return;
        }
        if (pdoDrag) {
          const span = pdoDrag.t1 - pdoDrag.t0;
          const plotW = Math.max(1, pdoDrag.w - PDO_PAD.left - PDO_PAD.right);
          const dx = e.clientX - pdoDrag.x;
          const dt = (dx / plotW) * span;
          let t0 = pdoDrag.t0 - dt;
          let t1 = pdoDrag.t1 - dt;
          const full = Math.max(pdoDuration || 1e-6, 1e-6);
          if (t0 < 0) { t1 -= t0; t0 = 0; }
          if (t1 > full) { t0 -= t1 - full; t1 = full; }
          if (t0 < 0) t0 = 0;
          pdoView = { t0, t1 };
          pdoCursorT = Math.min(pdoView.t1, Math.max(pdoView.t0, pdoXToTime(x, w)));
          hidePdoMeasureTooltip();
          drawPdoAll();
          return;
        }

        const hoverT = Math.min(pdoView.t1, Math.max(pdoView.t0, pdoXToTime(x, w)));
        pdoCursorT = hoverT;
        let activeEv = events[0];
        for (let i = 0; i < events.length; i++) {
          if (events[i].t <= hoverT) activeEv = events[i];
          else break;
        }
        if (activeEv) {
          cursorReadout.textContent = `時間: ${pdoFmtTime(hoverT)} (${hoverT.toFixed(6)}s) | CH${ch.index + 1} (${ch.loc_label}) 數值 = ${activeEv.val_str} (Frame #${activeEv.n})`;
        }

        const hit = findPdoMeasureAt(x, y, w);
        if (hit) {
          pdoHoveredMeasure = { id: hit.measure.id, ch };
          showPdoMeasureTooltip(hit.measure, ch, e.clientX, e.clientY);
        } else {
          pdoHoveredMeasure = null;
          hidePdoMeasureTooltip();
        }
        canvasWrap.style.cursor = hit && hit.isClose ? 'pointer' : (pdoMeasureMode ? 'col-resize' : 'crosshair');
        drawPdoAll();
      });

      const endPdoDrag = (e) => {
        if (pdoMeasureDrag) {
          if (canvasWrap.hasPointerCapture(e.pointerId)) {
            canvasWrap.releasePointerCapture(e.pointerId);
          }
          const cRect = canvasWrap.getBoundingClientRect();
          const w = Math.max(cRect.width, 1);
          const pxSpan = Math.abs(pdoTimeToX(pdoMeasureDrag.currT, w) - pdoTimeToX(pdoMeasureDrag.startT, w));
          if (pxSpan >= 4) {
            const id = pdoNextMeasureId++;
            pdoMeasures.push({
              id,
              t0: Math.min(pdoMeasureDrag.startT, pdoMeasureDrag.currT),
              t1: Math.max(pdoMeasureDrag.startT, pdoMeasureDrag.currT),
              color: PDO_MEASURE_COLORS[(id - 1) % PDO_MEASURE_COLORS.length],
            });
            updatePdoMeasureButtons();
          }
          pdoMeasureDrag = null;
          drawPdoAll();
          return;
        }
        if (pdoDrag && canvasWrap.hasPointerCapture(e.pointerId)) {
          canvasWrap.releasePointerCapture(e.pointerId);
        }
        pdoDrag = null;
      };

      canvasWrap.addEventListener('pointerup', endPdoDrag);
      canvasWrap.addEventListener('pointercancel', endPdoDrag);

      canvasWrap.addEventListener('contextmenu', (e) => {
        const cRect = canvasWrap.getBoundingClientRect();
        const w = Math.max(cRect.width, 1);
        const x = e.clientX - cRect.left;
        const y = e.clientY - cRect.top;
        const hit = findPdoMeasureAt(x, y, w);
        if (!hit) return;
        e.preventDefault();
        pdoMeasures = pdoMeasures.filter(m => m.id !== hit.measure.id);
        if (pdoHoveredMeasure && pdoHoveredMeasure.id === hit.measure.id) pdoHoveredMeasure = null;
        hidePdoMeasureTooltip();
        updatePdoMeasureButtons();
        drawPdoAll();
      });

      canvasWrap.addEventListener('pointerleave', () => {
        if (pdoDrag || pdoMeasureDrag) return;
        pdoCursorT = null;
        pdoHoveredMeasure = null;
        hidePdoMeasureTooltip();
        canvasWrap.style.cursor = pdoMeasureMode ? 'col-resize' : 'crosshair';
        cursorReadout.textContent = PDO_DEFAULT_HINT;
        drawPdoAll();
      });
    });

    updatePdoMeasureButtons();
    requestAnimationFrame(drawPdoAll);
  }

  pdoAxisWrap.addEventListener('wheel', (e) => {
    e.preventDefault();
    const rect = pdoAxisWrap.getBoundingClientRect();
    const factor = e.deltaY > 0 ? 1.18 : 1 / 1.18;
    pdoZoomAt(e.clientX - rect.left, Math.max(rect.width, 1), factor);
  }, { passive: false });
  pdoAxisWrap.addEventListener('dblclick', pdoResetView);

  pdoFullBtn.addEventListener('click', pdoResetView);
  pdoMeasureBtn.addEventListener('click', () => {
    pdoMeasureMode = !pdoMeasureMode;
    updatePdoMeasureButtons();
  });
  pdoClearMeasuresBtn.addEventListener('click', () => {
    pdoMeasures = [];
    pdoHoveredMeasure = null;
    hidePdoMeasureTooltip();
    updatePdoMeasureButtons();
    drawPdoAll();
  });

  helperPanel.style.display = 'none';
  helperToggle.addEventListener('click', () => {
    helperPanel.style.display = helperPanel.style.display === 'none' ? 'flex' : 'none';
    updatePdoPreview();
  });

  function buildPdoSyntax() {
    const base = pdoBase.value.trim() || 'ecat';
    const byteIdx = parseInt(pdoByte.value || '0', 10);
    const dtype = pdoDtype.value;
    const dg = parseInt(pdoDg.value || '0', 10);
    let offsetPart = `${byteIdx}`;
    if (dtype === 'bit') {
      offsetPart = `${byteIdx}.${parseInt(pdoBit.value || '0', 10)}`;
    } else if (dtype === 'hex') {
      offsetPart = `${byteIdx}:${parseInt(pdoLen.value || '1', 10)}`;
    }
    return `pdo: ${base} | ${offsetPart} | ${dtype} | ${dg}`;
  }

  function updatePdoPreview() {
    const dtype = pdoDtype.value;
    pdoBitWrap.style.display = dtype === 'bit' ? 'inline-block' : 'none';
    pdoLenWrap.style.display = dtype === 'hex' ? 'inline-block' : 'none';
    pdoPreview.textContent = buildPdoSyntax();
  }

  function getChannelFilterInputs() {
    const chInputs = Array.from(document.querySelectorAll('#channels input'));
    if (chInputs.length > 0) return chInputs;
    return Array.from(document.querySelectorAll('input')).filter(i => !i.closest('#live-capture-bar'));
  }

  function triggerScanButton() {
    const runBtn = document.getElementById('run') || Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === '掃描');
    if (runBtn) runBtn.click();
  }

  [pdoBase, pdoByte, pdoDtype, pdoBit, pdoLen, pdoDg].forEach(el => {
    el.addEventListener('input', updatePdoPreview);
    el.addEventListener('change', updatePdoPreview);
    el.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        const syntax = buildPdoSyntax();
        const inputs = getChannelFilterInputs();
        if (!inputs.some(i => i.value.trim() === syntax)) {
          const emptyInput = inputs.find(i => !i.value.trim());
          if (emptyInput) {
            emptyInput.value = syntax;
            emptyInput.dispatchEvent(new Event('input', { bubbles: true }));
            emptyInput.dispatchEvent(new Event('change', { bubbles: true }));
            pdoPreview.textContent = `已填入頻道並觸發掃描: ${syntax}`;
          }
        }
        triggerScanButton();
      }
    });
  });

  pdoCopyBtn.addEventListener('click', () => {
    const syntax = buildPdoSyntax();
    navigator.clipboard?.writeText(syntax).catch(() => {});
    const inputs = getChannelFilterInputs();
    const emptyInput = inputs.find(i => !i.value.trim());
    if (emptyInput) {
      emptyInput.value = syntax;
      emptyInput.dispatchEvent(new Event('input', { bubbles: true }));
      emptyInput.dispatchEvent(new Event('change', { bubbles: true }));
      pdoPreview.textContent = `已填入頻道並觸發掃描: ${syntax}`;
      triggerScanButton();
    } else {
      pdoPreview.textContent = `已複製到剪貼簿: ${syntax}`;
    }
  });

  async function loadInterfaces() {
    try {
      const res = await fetch('/api/interfaces');
      const data = await res.json();
      if (data.interfaces && data.interfaces.length > 0) {
        ifaceSelect.innerHTML = data.interfaces.map(i => `<option value="${i.id}">${i.id}. ${i.name}</option>`).join('');
      } else {
        ifaceSelect.innerHTML = '<option value="">找不到可用網卡</option>';
      }
    } catch (e) {
      ifaceSelect.innerHTML = '<option value="">讀取網卡失敗</option>';
    }
  }

  function triggerRefreshAndScan() {
    const buttons = Array.from(document.querySelectorAll('button'));
    const refreshBtn = buttons.find(b => b.textContent.trim() === '重新整理');
    const scanBtn = buttons.find(b => b.textContent.trim() === '掃描');
    const fileSelect = document.querySelector('select:not(#live-iface):not(#pdo-dtype)');

    if (fileSelect) {
      const hasLiveOption = Array.from(fileSelect.options).some(o => o.value === 'live_capture.pcap');
      if (!hasLiveOption && refreshBtn) {
        refreshBtn.click();
      }
      if (fileSelect.value !== 'live_capture.pcap') {
        fileSelect.value = 'live_capture.pcap';
        fileSelect.dispatchEvent(new Event('change'));
      }
    }
    if (scanBtn) {
      scanBtn.click();
    }
  }

  function updateUIState(running, iface) {
    isLive = running;
    if (running) {
      toggleBtn.textContent = '停止監控';
      toggleBtn.style.background = '#ef4444';
      ifaceSelect.disabled = true;
      statusSpan.textContent = `🔴 正在錄製網卡 #${iface} (每 1.5 秒自動更新示波器)...`;
      statusSpan.style.color = '#fca5a5';
      if (!pollTimer) {
        pollTimer = setInterval(triggerRefreshAndScan, 1500);
      }
    } else {
      toggleBtn.textContent = '開始即時監控';
      toggleBtn.style.background = '#10b981';
      ifaceSelect.disabled = false;
      statusSpan.textContent = '待機中';
      statusSpan.style.color = '#94a3b8';
      if (pollTimer) {
        clearInterval(pollTimer);
        pollTimer = null;
      }
    }
  }

  toggleBtn.addEventListener('click', async () => {
    toggleBtn.disabled = true;
    try {
      if (!isLive) {
        const iface = ifaceSelect.value;
        if (!iface) return alert('請先選擇網路介面卡');
        const res = await fetch('/api/capture/start', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({interface: iface})
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || '啟動失敗');
        updateUIState(true, iface);
        setTimeout(triggerRefreshAndScan, 600);
      } else {
        await fetch('/api/capture/stop', {method: 'POST'});
        updateUIState(false, null);
      }
    } catch (err) {
      alert(err.message);
    } finally {
      toggleBtn.disabled = false;
    }
  });

  loadInterfaces().then(async () => {
    const res = await fetch('/api/capture/status');
    const st = await res.json();
    if (st.running) updateUIState(true, st.interface);
  });
})();
</script>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write("%s\n" % (fmt % args))

    def send_json(self, payload, status=200):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_html_with_live_ui(self, path):
        html = path.read_text(encoding="utf-8", errors="replace")
        if "<body" in html.lower():
            html = re.sub(
                r"(<body[^>]*>)",
                lambda m: m.group(1) + LIVE_UI_INJECTION,
                html,
                count=1,
                flags=re.IGNORECASE,
            )
        else:
            html = LIVE_UI_INJECTION + html
        data = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_html_with_live_ui(STATIC / "index.html")
            return
        if parsed.path == "/api/files":
            self.send_json({"files": list_captures()})
            return
        if parsed.path == "/api/interfaces":
            try:
                self.send_json({"interfaces": list_interfaces()})
            except RuntimeError as exc:
                self.send_json({"error": str(exc)}, 500)
            return
        if parsed.path == "/api/capture/status":
            self.send_json(capture_status())
            return
        if parsed.path == "/api/meta":
            try:
                name = parse_qs(parsed.query).get("file", [""])[0]
                self.send_json(capture_meta(resolve_capture(name)))
            except (ValueError, RuntimeError) as exc:
                self.send_json({"error": str(exc)}, 400)
            return
        self.send_json({"error": "找不到路徑"}, 404)

    def do_POST(self):
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length > MAX_BODY:
            self.send_json({"error": "請求過大"}, 413)
            return

        if parsed.path == "/api/capture/start":
            try:
                payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                iface = payload.get("interface", "")
                if not iface:
                    raise ValueError("請指定網路介面卡")
                self.send_json(start_live_capture(iface))
            except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 400)
            return

        if parsed.path == "/api/capture/stop":
            stop_live_capture()
            self.send_json({"stopped": True})
            return

        if parsed.path != "/api/scan":
            self.send_json({"error": "找不到路徑"}, 404)
            return

        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            path = resolve_capture(payload.get("file", ""))
            filters = payload.get("filters", [])
            if not isinstance(filters, list):
                raise ValueError("filters 必須是陣列")
            filters = [item if isinstance(item, str) else "" for item in filters]
            self.send_json(scan_all(path, filters))
        except json.JSONDecodeError:
            self.send_json({"error": "JSON 格式錯誤"}, 400)
        except (ValueError, RuntimeError) as exc:
            self.send_json({"error": str(exc)}, 400)


class ReusableThreadingHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True  # 關鍵：主程式關閉時，強制一起結束所有網頁連線執行緒

def kill_previous_instance(port):
    """啟動前自動清理佔用同一個 Port 的舊行程 (macOS / Linux)"""
    if os.name != "nt":
        my_pid = str(os.getpid())
        res = subprocess.run(["lsof", "-ti", f":{port}"], capture_output=True, text=True)
        for pid in res.stdout.split():
            if pid and pid != my_pid:
                try:
                    os.kill(int(pid), 9)
                except OSError:
                    pass
        time.sleep(0.2)

def main():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
    if not STATIC.joinpath("index.html").is_file():
        sys.exit("缺少 static/index.html")
    
    kill_previous_instance(PORT)  # 啟動前自動清空殘留的舊行程
    server = ReusableThreadingHTTPServer((HOST, PORT), Handler)
    print("封包示波器 (支援即時抓包 & EtherCAT PDO 數值波形) http://%s:%d" % (HOST, PORT), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n正在關閉伺服器...", flush=True)
    finally:
        stop_live_capture()
        server.server_close()
        os._exit(0)  # 關鍵：確保不會被背景子執行緒卡住，立刻完全退出


if __name__ == "__main__":
    main()
