import asyncio
import json
import time
import sqlite3
from datetime import datetime
from bleak import BleakScanner
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
import uvicorn
from contextlib import asynccontextmanager

DB_FILE = "heartrate.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS hr_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp_ms INTEGER,
        hr_value INTEGER,
        rssi INTEGER,
        raw_data TEXT
    )''')
    c.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON hr_logs(timestamp_ms)')
    # 会话表：记录每次扫描会话的生命周期
    c.execute('''CREATE TABLE IF NOT EXISTS scan_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        start_ms INTEGER NOT NULL,
        end_ms INTEGER DEFAULT NULL
    )''')
    # 为 hr_logs 添加 session_id 列（兼容已有数据库）
    try:
        c.execute('ALTER TABLE hr_logs ADD COLUMN session_id INTEGER DEFAULT NULL')
    except Exception:
        pass  # 列已存在时忽略
    c.execute('CREATE INDEX IF NOT EXISTS idx_session_id ON hr_logs(session_id)')
    c.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT
    )''')
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('retention_hours', '72')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('target_mac', '')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('chart_duration_s', '300')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('chart_refresh_interval', '1.0')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('hr_threshold', '160')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('duplicate_filter_ms', '10')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('manuf_id', '343')")
    conn.commit()
    conn.close()

class DeviceState:
    def __init__(self):
        self.connected_websockets = []
        self.scan_websockets = []  # 扫描页面的 WebSocket 连接
        self.is_scanning = False
        self.scanner = None
        
        self.current_hr = 0
        self.rssi = 0
        self.device_name = "未知设备"
        self.raw_data_hex = ""
        self.last_update = "尚未接收到数据"
        self.refresh_interval_ms = 0
        self.refresh_hz = 0.0
        
        self.session_start_time = 0
        self.session_packet_count = 0
        self.current_session_id = None
        
        # 扫描页面：记录所有发现设备的广播数据
        self.scan_devices = {}  # {mac: {...完整广播信息}}
        self.scan_device_count = 0  # 累计发现的唯一设备总数
        
        # Load from DB parameters
        self.load_settings()

    def load_settings(self):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT key, value FROM settings')
        rows = c.fetchall()
        d = {k: v for k, v in rows}
        conn.close()
        
        self.target_mac = d.get('target_mac', '')
        self.chart_duration_s = int(d.get('chart_duration_s', 300))
        self.chart_refresh_interval = float(d.get('chart_refresh_interval', 1.0))
        self.hr_threshold = int(d.get('hr_threshold', 160))
        self.duplicate_filter_ms = int(d.get('duplicate_filter_ms', 10))
        self.retention_hours = int(d.get('retention_hours', 72))
        self.manuf_id = int(d.get('manuf_id', 343))

    def save_setting(self, key, value):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('REPLACE INTO settings (key, value) VALUES (?, ?)', (key, str(value)))
        conn.commit()
        conn.close()
        self.load_settings()

init_db()
state = DeviceState()

# ================= 核心推流与循环逻辑 =================
async def broadcast_update():
    """向所有连接的监控面板 WebSocket 广播心率提取数据"""
    if not state.connected_websockets:
        return
    
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    now_ms = int(time.time() * 1000)
    
    if state.is_scanning and state.session_start_time > 0:
        elapsed_s = (now_ms - state.session_start_time) / 1000.0
        session_time_text = f"{int(elapsed_s // 60):02d}:{int(elapsed_s % 60):02d}"
        if state.session_packet_count > 1 and elapsed_s > 0:
            avg_hz = round(state.session_packet_count / elapsed_s, 2)
            avg_interval_ms = int((elapsed_s / state.session_packet_count) * 1000)
        else:
            avg_hz = 0.0
            avg_interval_ms = 0
    else:
        session_time_text = "PAUSED"
        avg_hz = 0.0
        avg_interval_ms = 0


    c.execute('SELECT MAX(timestamp_ms) FROM hr_logs')
    res = c.fetchone()
    max_ts = res[0] or 0
    raw_time_since = (now_ms - max_ts) if max_ts > 0 else 0
    time_since_last_display = str(raw_time_since) if state.is_scanning else "--"
                
    cutoff_ms = now_ms - (state.chart_duration_s * 1000)
    c.execute('SELECT timestamp_ms, hr_value, rssi FROM hr_logs WHERE timestamp_ms >= ? ORDER BY timestamp_ms ASC', (cutoff_ms,))
    rows = c.fetchall()
    
    # 查询可视窗口内的所有扫描会话区间
    c.execute('''SELECT id, start_ms, COALESCE(end_ms, ?) as end_ms
                 FROM scan_sessions
                 WHERE start_ms < ? AND (end_ms IS NULL OR end_ms > ?)
                 ORDER BY start_ms ASC''', (now_ms, now_ms, cutoff_ms))
    sessions = c.fetchall()
    conn.close()

    # 辅助函数：判定某时间点所属的会话 ID
    def get_session_id_at(ts):
        for sid, s_start, s_end in sessions:
            if s_start <= ts <= s_end:
                return sid
        return None

    interval_ms = int(state.chart_refresh_interval * 1000)
    limit = int(state.chart_duration_s / state.chart_refresh_interval)
    
    hr_arr = []
    rssi_arr = []
    time_arr = []
    fresh_arr = []
    session_id_arr = []
    
    idx = 0
    row_len = len(rows)
    
    # 按会话追踪最近已知值，用于右端锚点（防止跨会话泄漏）
    session_last_hr = {}   # {session_id: last_hr_value}
    session_last_rssi = {} # {session_id: last_rssi_value}
    
    for i in range(limit):
        target = cutoff_ms + i * interval_ms
        last_hr = None
        last_rssi = None
        fresh = False
        while idx < row_len and rows[idx][0] < target + interval_ms:
            last_hr = rows[idx][1]
            last_rssi = rows[idx][2]
            idx += 1
            fresh = True
        
        sid = get_session_id_at(target)
        session_id_arr.append(sid)
        
        if fresh and sid is not None:
            session_last_hr[sid] = last_hr
            session_last_rssi[sid] = last_rssi
        
        if fresh:
            # 有实际数据 → 放入
            hr_arr.append(last_hr)
            rssi_arr.append(last_rssi)
        elif i == limit - 1 and sid is not None and sid in session_last_hr:
            # 当前会话右端锚点：仅使用本会话的数据保持连线到图表最右侧
            hr_arr.append(session_last_hr[sid])
            rssi_arr.append(session_last_rssi[sid])
        else:
            # 无数据 → null（绝不填充旧值，避免阶梯突变）
            hr_arr.append(None)
            rssi_arr.append(None)
        
        dt = datetime.fromtimestamp(target / 1000.0)
        time_arr.append(dt.strftime("%H:%M:%S"))
        fresh_arr.append(fresh)

    data = json.dumps({
        "settings": {
            "mac": state.target_mac,
            "manuf_id": state.manuf_id,
            "duration": state.chart_duration_s,
            "refresh": state.chart_refresh_interval,
            "filter": state.duplicate_filter_ms,
            "threshold": state.hr_threshold,
            "limit": limit,
            "retention": state.retention_hours
        },
        "stats": {
            "is_scanning": state.is_scanning,
            "hr": state.current_hr if state.is_scanning else 0,
            "rssi": state.rssi if state.is_scanning else "--",
            "name": state.device_name,
            "raw": state.raw_data_hex,
            "time": state.last_update,
            "interval_ms": state.refresh_interval_ms,
            "hz": state.refresh_hz,
            "session_time_text": session_time_text,
            "time_since_last_display": time_since_last_display,
            "avg_interval_ms": avg_interval_ms if avg_interval_ms > 0 else "--",
            "avg_hz": avg_hz
        },
        "history": {
            "hr": hr_arr,
            "rssi": rssi_arr,
            "time": time_arr,
            "fresh": fresh_arr,
            "session_ids": session_id_arr
        }
    })
    
    for ws in state.connected_websockets.copy():
        try:
            await ws.send_text(data)
        except Exception:
            state.connected_websockets.remove(ws)

async def broadcast_scan_update():
    """向所有扫描页面 WebSocket 广播设备列表"""
    if not state.scan_websockets:
        return
    
    data = json.dumps({
        "devices": state.scan_devices,
        "is_scanning": state.is_scanning,
        "total": state.scan_device_count
    })
    
    for ws in state.scan_websockets.copy():
        try:
            await ws.send_text(data)
        except Exception:
            if ws in state.scan_websockets:
                state.scan_websockets.remove(ws)

async def background_tick_loop():
    """定时触发广播与数据库清理"""
    scan_tick_acc = 0.0  # 扫描页面广播累计计时器
    while True:
        target_interval = state.chart_refresh_interval
        await asyncio.sleep(target_interval)
        scan_tick_acc += target_interval
            
        await broadcast_update()
        
        # 扫描页面每 ~1 秒广播一次（避免大量设备数据高频推送）
        if scan_tick_acc >= 1.0:
            scan_tick_acc = 0.0
            await broadcast_scan_update()
        
        # 自动清理超出最长保存时间的数据
        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            cutoff = int(time.time() * 1000) - (state.retention_hours * 3600 * 1000)
            c.execute('DELETE FROM hr_logs WHERE timestamp_ms < ?', (cutoff,))
            c.execute('DELETE FROM scan_sessions WHERE end_ms IS NOT NULL AND end_ms < ?', (cutoff,))
            conn.commit()
            conn.close()
        except Exception as e:
            print("清理错误:", e)

# ================= 蓝牙接收回调 =================
def detection_callback(device, advertisement_data):
    # ===== 全局设备扫描记录（供 /scan 页面使用）=====
    now_ms = int(time.time() * 1000)
    mac = device.address.upper()
    
    # 提取所有制造商数据
    manuf_data_all = {}
    for mid, mdata in advertisement_data.manufacturer_data.items():
        manuf_data_all[str(mid)] = {
            "hex": mdata.hex().upper(),
            "bytes": list(mdata),
            "length": len(mdata)
        }
    
    # 提取服务数据
    service_data_all = {}
    if advertisement_data.service_data:
        for uuid, sdata in advertisement_data.service_data.items():
            service_data_all[uuid] = {
                "hex": sdata.hex().upper(),
                "bytes": list(sdata),
                "length": len(sdata)
            }
    
    is_new = mac not in state.scan_devices
    
    state.scan_devices[mac] = {
        "name": device.name or advertisement_data.local_name or "",
        "mac": mac,
        "rssi": advertisement_data.rssi,
        "manufacturer_data": manuf_data_all,
        "service_uuids": list(advertisement_data.service_uuids) if advertisement_data.service_uuids else [],
        "service_data": service_data_all,
        "tx_power": advertisement_data.tx_power,
        "last_seen_ms": now_ms,
        "last_seen_text": datetime.now().strftime("%H:%M:%S.%f")[:-3],
        "hit_count": state.scan_devices.get(mac, {}).get("hit_count", 0) + 1,
        "first_seen_text": state.scan_devices.get(mac, {}).get("first_seen_text", datetime.now().strftime("%H:%M:%S.%f")[:-3])
    }
    
    if is_new:
        state.scan_device_count += 1
    
    # ===== 原有心率数据过滤逻辑 =====
    if not state.target_mac or device.address.upper() != state.target_mac.upper():
        return
        
    manuf_data = advertisement_data.manufacturer_data.get(state.manuf_id)
    if manuf_data and len(manuf_data) > 3:
        heart_rate = manuf_data[3]
        if 0 < heart_rate < 255:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute('SELECT MAX(timestamp_ms) FROM hr_logs')
            res = c.fetchone()
            last_ts = res[0] or 0
            
            delta_ms = now_ms - last_ts
            if last_ts > 0 and delta_ms < state.duplicate_filter_ms:
                conn.close()
                return

            c.execute('INSERT INTO hr_logs (timestamp_ms, hr_value, rssi, raw_data, session_id) VALUES (?, ?, ?, ?, ?)',
                     (now_ms, heart_rate, advertisement_data.rssi, manuf_data.hex().upper(), state.current_session_id))
            conn.commit()
            conn.close()
            
            state.session_packet_count += 1
            state.current_hr = heart_rate
            state.rssi = advertisement_data.rssi
            state.raw_data_hex = manuf_data.hex().upper()
            state.device_name = device.name or advertisement_data.local_name or "未知设备"
            state.last_update = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            state.refresh_interval_ms = delta_ms if last_ts > 0 else 0
            state.refresh_hz = round(1000.0 / delta_ms, 2) if delta_ms > 0 else 0.0

            try:
                with open("heartrate.txt", "w", encoding="utf-8") as f:
                    f.write(str(heart_rate))
            except Exception:
                pass

# ================= FastAPI 后端 =================
@asynccontextmanager
async def lifespan(app: FastAPI):
    print("🚀 正在启动后台蓝牙扫描...")
    state.scanner = BleakScanner(detection_callback)
    await state.scanner.start()
    state.is_scanning = True
    state.session_start_time = int(time.time() * 1000)
    state.session_packet_count = 0
    
    # 创建新的扫描会话
    now_ms = int(time.time() * 1000)
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO scan_sessions (start_ms) VALUES (?)', (now_ms,))
    state.current_session_id = c.lastrowid
    conn.commit()
    conn.close()
    print(f"📋 会话 #{state.current_session_id} 已创建")
    
    ticker_task = asyncio.create_task(background_tick_loop())
    
    yield
    print("🛑 正在停止蓝牙扫描...")
    if state.is_scanning and state.scanner:
        try:
            await state.scanner.stop()
        except Exception:
            pass
    # 关闭当前扫描会话
    if state.current_session_id is not None:
        end_ms = int(time.time() * 1000)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('UPDATE scan_sessions SET end_ms = ? WHERE id = ?', (end_ms, state.current_session_id))
        conn.commit()
        conn.close()
        print(f"📋 会话 #{state.current_session_id} 已关闭")
        state.current_session_id = None
    state.is_scanning = False
    ticker_task.cancel()

app = FastAPI(lifespan=lifespan)

# ================= 前端模板：OBS 直播组件 =================
HTML_LIVE = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <title>OBS Live Overlay</title>
    <style>
        body { margin: 0; padding: 0; background-color: transparent; font-family: 'Segoe UI', sans-serif; overflow: hidden; }
        .widget {
            display: inline-flex; align-items: center;
            background: rgba(10, 10, 10, 0.85); backdrop-filter: blur(6px);
            border: 1px solid rgba(255, 255, 255, 0.1); padding: 8px 20px;
            border-radius: 50px; color: #ffffff; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.5);
        }
        .heart { color: #ef4444; font-size: 32px; margin-right: 12px; display: inline-block; transform: translateY(-3px); }
        .heartbeat { animation: pump 1s infinite ease-out; }
        @keyframes pump { 0% { transform: translateY(-3px) scale(1); } 30% { transform: translateY(-3px) scale(1.3); } 100% { transform: translateY(-3px) scale(1); } }
        .hr-value { font-size: 42px; font-weight: 900; font-family: monospace; letter-spacing: -2px;}
        .hr-warning { color: #ef4444; }
        .unit { font-size: 16px; color: #9ca3af; margin-left: 6px; font-weight: normal; }
    </style>
</head>
<body>
    <div class="widget" id="widget">
        <div id="heart-icon" class="heart">❤️</div>
        <div class="hr-value"><span id="hr-value">--</span><span class="unit">BPM</span></div>
    </div>
    <script>
        let ws;
        function connect() {
            ws = new WebSocket(`ws://${window.location.host}/ws`);
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                if(data.stats.hr > 0) {
                    const hrEl = document.getElementById('hr-value');
                    hrEl.innerText = data.stats.hr;
                    
                    if (data.stats.hr >= data.settings.threshold) hrEl.classList.add('hr-warning');
                    else hrEl.classList.remove('hr-warning');

                    const heart = document.getElementById('heart-icon');
                    if (!heart.classList.contains('heartbeat')) heart.classList.add('heartbeat');
                    heart.style.animationDuration = (60 / data.stats.hr).toFixed(3) + 's';
                } else {
                    document.getElementById('hr-value').innerText = "--";
                    document.getElementById('hr-value').classList.remove('hr-warning');
                    document.getElementById('heart-icon').classList.remove('heartbeat');
                }
            };
            ws.onclose = function() {
                document.getElementById('hr-value').innerText = "--";
                setTimeout(connect, 2000);
            };
        }
        connect();
    </script>
</body>
</html>
"""

# ================= 前端模板：主控排版重构版 =================
HTML_DASHBOARD = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BLE 实时数据展示</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { background-color: #050505; color: #e5e5e5; }
        .glass { background: rgba(15, 15, 15, 0.7); backdrop-filter: blur(16px); border: 1px solid #262626; box-shadow: inset 0 1px 0 rgba(255,255,255,0.05); }
        input[type="text"] { background: #171717; border: 1px solid #404040; color: #e5e5e5; outline: none; transition: border 0.2s; }
        input[type="text"]:focus { border-color: #ef4444; }
        /* 极致发光滑块 */
        input[type="range"]::-webkit-slider-thumb {
            -webkit-appearance: none; height: 16px; width: 16px; border-radius: 50%;
            background: #ffffff; cursor: pointer; box-shadow: 0 0 12px rgba(255,255,255,0.4);
        }
        input[type="range"]::-moz-range-thumb {
            height: 16px; width: 16px; border-radius: 50%; background: #ffffff;
            cursor: pointer; border: none; box-shadow: 0 0 12px rgba(255,255,255,0.4);
        }
        /* 吸附刻度标记样式 */
        .tick-marks {
            display: flex; justify-content: space-between; padding: 2px 0 0 0;
            position: relative; height: 18px; pointer-events: none;
            margin: 0 8px; /* 与滑块手柄半径(16px/2)对齐 */
        }
        .tick-mark {
            display: flex; flex-direction: column; align-items: center;
            position: absolute; transform: translateX(-50%);
        }
        .tick-mark::before {
            content: ''; display: block; width: 1px; height: 5px;
            background: rgba(115, 115, 115, 0.5); margin-bottom: 1px;
        }
        .tick-label {
            font-size: 8px; color: #525252; font-family: monospace;
            white-space: nowrap; letter-spacing: -0.5px;
        }
        @keyframes hr-glow-pulse { 0% { opacity: 0.15; transform: scale(0.9); } 30% { opacity: 0.5; transform: scale(1.05); } 100% { opacity: 0.15; transform: scale(0.9); } }
        .pulsing-glow { animation: hr-glow-pulse 1s infinite ease-out; }
    </style>
</head>
<body class="p-4 md:p-8 min-h-screen font-sans flex justify-center">
    <div class="max-w-7xl w-full space-y-6">
        
        <!-- HEADER -->
        <div class="glass flex justify-between items-center rounded-2xl p-6 shadow-2xl relative overflow-hidden group">
           <div class="absolute inset-x-0 -top-10 h-20 bg-neutral-600/10 blur-2xl pointer-events-none transition duration-500 group-hover:bg-neutral-600/20"></div>
           <div class="relative z-10">
                <h1 class="text-2xl md:text-3xl font-black text-white tracking-widest uppercase">BLE 实时心率展示</h1>
                <p class="text-xs text-neutral-500 mt-2 font-mono">OBS极简心率组件: <a href="/live" target="_blank" class="text-neutral-400 hover:text-white transition bg-neutral-900 px-2 py-0.5 rounded cursor-pointer">http://127.0.0.1:8000/live</a> · <a href="/scan" target="_blank" class="text-neutral-400 hover:text-white transition bg-neutral-900 px-2 py-0.5 rounded cursor-pointer">📡 设备扫描探测器</a></p>
           </div>
           <div class="flex flex-col items-end relative z-10">
               <button onclick="toggleScan()" class="group/btn flex items-center gap-3 bg-neutral-900 px-4 py-2 rounded-full border border-neutral-800 hover:border-neutral-700 transition cursor-pointer shadow-inner">
                   <div id="status-dot" class="relative flex h-2.5 w-2.5">
                       <span class="animate-ping absolute h-full w-full rounded-full bg-emerald-500 opacity-75"></span>
                       <span class="relative h-2.5 w-2.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]"></span>
                   </div>
                   <span id="status-text" class="text-sm font-bold text-emerald-400 tracking-wider group-hover/btn:opacity-80 transition">AWAITING...</span>
               </button>
               <span id="update-time" class="text-[11px] text-neutral-600 font-mono mt-2 pr-2 leading-none">--</span>
           </div>
        </div>

        <!-- HERO SECTION -->
        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <!-- 心率展示主塔 -->
            <div class="glass rounded-2xl p-8 flex flex-col items-center justify-center lg:col-span-1 relative overflow-hidden group border-t border-t-neutral-800/80">
                <div id="hr-glow-bg" class="absolute -inset-10 bg-red-500/20 blur-3xl opacity-0 transition-opacity duration-500 pointer-events-none rounded-full"></div>
                <div class="absolute inset-0 bg-gradient-to-b from-neutral-800/10 to-transparent pointer-events-none"></div>
                <div class="text-neutral-500 mb-3 font-bold tracking-widest text-xs uppercase z-10">当前实时心率</div>
                <div class="flex items-baseline gap-2 z-10 transition-transform duration-300 transform group-hover:scale-105">
                    <span id="hr-value" class="text-8xl md:text-9xl font-black font-mono tracking-tighter text-white drop-shadow-2xl transition-colors duration-300">--</span>
                </div>
                <div class="text-xl font-bold text-neutral-600 z-10 mt-[-10px] mb-4">BPM</div>
                <div id="device-name" class="px-4 py-1.5 bg-black/40 border border-neutral-800/50 rounded-full text-xs text-neutral-400 font-mono shadow-inner z-10 truncate max-w-full">系统初始化中...</div>
            </div>

            <!-- 数据波束图床 -->
            <div class="glass rounded-2xl p-4 lg:col-span-3 relative md:min-h-[380px] min-h-[250px] flex flex-col overflow-hidden group">
                <div class="absolute -right-20 -bottom-20 w-64 h-64 bg-red-500/5 rounded-full blur-3xl pointer-events-none transition duration-500 group-hover:bg-red-500/10"></div>
                <div class="absolute top-4 left-6 z-10 flex items-center gap-4">
                    <div class="text-[10px] font-bold text-neutral-700 tracking-[0.2em] uppercase origin-left">变化折线图</div>
                    <div class="flex bg-neutral-900/80 backdrop-blur-sm rounded-lg p-0.5 border border-neutral-800">
                        <button onclick="setChartMode('hr')" id="btn-mode-hr" class="px-2.5 py-1 text-[10px] rounded hover:bg-neutral-800 text-red-500 font-bold tracking-wider transition">心率</button>
                        <button onclick="setChartMode('rssi')" id="btn-mode-rssi" class="px-2.5 py-1 text-[10px] rounded hover:bg-neutral-800 text-neutral-500 tracking-wider transition">信号</button>
                    </div>
                </div>
                <div class="flex-1 w-full h-full pt-8">
                    <canvas id="hrChart"></canvas>
                </div>
            </div>
        </div>

        <!-- STATUS BAR -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-6">
            <div class="glass rounded-2xl p-5 flex flex-col justify-center relative overflow-hidden group">
                <div class="absolute -right-4 -top-4 w-16 h-16 bg-neutral-500/10 rounded-full blur-xl transition duration-500 group-hover:bg-neutral-500/20 pointer-events-none"></div>
                <div class="text-xs text-neutral-500 mb-2 font-semibold uppercase tracking-widest relative z-10">信号强度</div>
                <div class="flex items-center gap-3 relative z-10">
                    <span id="rssi-value" class="font-mono text-lg text-white w-20">-- dBm</span>
                    <div class="flex-1 h-2 bg-neutral-900 rounded-full overflow-hidden shadow-inner">
                        <div id="rssi-bar" class="h-full bg-neutral-500 transition-all duration-300 w-0"></div>
                    </div>
                </div>
            </div>
            <div class="glass rounded-2xl p-5 flex flex-col justify-center gap-1 relative overflow-hidden group">
                <div class="absolute -right-4 -top-4 w-16 h-16 bg-blue-500/10 rounded-full blur-xl transition duration-500 group-hover:bg-blue-500/20 pointer-events-none"></div>
                <div class="flex justify-between items-end border-b border-neutral-800/80 pb-2 relative z-10">
                    <span class="text-[10px] text-neutral-500 font-semibold tracking-wider uppercase">瞬时空窗 (距上一包)</span>
                    <div class="font-mono tracking-tight"><span id="time-since-last" class="text-lg font-bold text-white drop-shadow-[0_0_8px_rgba(255,255,255,0.2)]">--</span> <span class="text-[10px] text-neutral-600 ml-0.5">ms</span></div>
                </div>
                <div class="flex justify-between items-end pt-2 relative z-10">
                    <span class="text-[10px] text-neutral-500 font-semibold tracking-wider uppercase">全局平均包间隔</span>
                    <div class="font-mono tracking-tight"><span id="avg-interval" class="text-sm font-bold text-blue-400">--</span> <span class="text-[10px] text-neutral-600 ml-0.5">ms</span></div>
                </div>
            </div>
            <div class="glass rounded-2xl p-5 flex flex-col justify-center relative overflow-hidden group">
                <div class="absolute -right-4 -top-4 w-16 h-16 bg-emerald-500/10 rounded-full blur-xl transition duration-500 group-hover:bg-emerald-500/20 pointer-events-none"></div>
                <div class="text-xs text-neutral-500 mb-2 font-semibold uppercase tracking-widest">单次扫描频率</div>
                <div class="flex items-end justify-between z-10 w-full mt-1">
                    <div class="font-mono tracking-tighter">
                        <span id="avg-hz-val" class="text-3xl font-bold text-emerald-400 drop-shadow-[0_0_12px_rgba(16,185,129,0.3)]">--</span>
                        <span class="text-xs text-neutral-600 font-sans ml-1 tracking-normal">Hz</span>
                    </div>
                    <div class="text-right flex flex-col items-end opacity-70">
                        <span class="text-[9px] text-neutral-500 uppercase tracking-widest mb-0.5">会话运行时长</span>
                        <span class="font-mono text-xs text-emerald-300" id="session-time-val">--</span>
                    </div>
                </div>
            </div>
            <div class="glass rounded-2xl p-5 flex flex-col justify-center relative overflow-hidden group">
                <div class="absolute -right-4 -top-4 w-16 h-16 bg-purple-500/10 rounded-full blur-xl transition duration-500 group-hover:bg-purple-500/20 pointer-events-none"></div>
                <div class="text-xs text-neutral-500 mb-2 font-semibold uppercase tracking-widest flex items-center justify-between relative z-10">
                    <span>制造商数据负载</span><span id="manuf-badge" class="bg-purple-900/40 text-purple-400 px-1.5 py-0.5 rounded text-[9px]">343</span>
                </div>
                <div class="font-mono text-[13px] text-purple-300 truncate bg-black/40 px-2 py-1.5 rounded border border-neutral-800 shadow-inner relative z-10" id="raw-data">--</div>
            </div>
        </div>

        <!-- SETTINGS PANEL -->
        <div class="glass rounded-2xl border-t border-solid border-neutral-800 shadow-2xl relative overflow-hidden group">
            <div class="absolute -top-10 -right-10 w-40 h-40 bg-red-900/15 rounded-full blur-3xl pointer-events-none transition duration-500 group-hover:bg-red-900/25"></div>
            <div class="absolute -bottom-10 -left-10 w-40 h-40 bg-blue-900/10 rounded-full blur-3xl pointer-events-none transition duration-500 group-hover:bg-blue-900/20"></div>
            
            <div class="flex flex-col md:flex-row p-6 md:p-8 gap-8 md:gap-12">
                <!-- MAC and Manuf ID Section -->
                <div class="md:w-1/3 flex flex-col justify-center gap-4">
                    <div>
                        <label class="text-xs font-bold text-neutral-500 uppercase tracking-widest block mb-2">监听捕获 MAC</label>
                        <input type="text" id="mac-input" spellcheck="false" class="w-full bg-black/50 border border-neutral-800 px-4 py-3 rounded-xl font-mono text-sm text-red-400 shadow-inner focus:border-red-500 transition placeholder-neutral-700" placeholder="00:11:22:33:44:55">
                    </div>
                    <div>
                        <label class="text-xs font-bold text-neutral-500 uppercase tracking-widest block mb-2">制造商 ID (十进制)</label>
                        <div class="flex gap-2">
                            <select id="manuf-select" class="bg-black/50 border border-neutral-800 px-3 py-3 rounded-xl text-sm text-white shadow-inner focus:border-neutral-500 transition outline-none w-1/2" onchange="document.getElementById('manuf-input').value = this.value">
                                <option value="343">小米 (343 / 0x0157)</option>
                                <option value="76">苹果 (76 / 0x004C)</option>
                                <option value="117">华为 (117 / 0x0075)</option>
                                <option value="87">三星 (87 / 0x0057)</option>
                                <option value="128">欧姆龙 (128 / 0x0080)</option>
                                <option value="0">自定义...</option>
                            </select>
                            <input type="number" id="manuf-input" class="w-1/2 bg-black/50 border border-neutral-800 px-3 py-3 rounded-xl font-mono text-sm text-white shadow-inner focus:border-neutral-500 transition placeholder-neutral-700" placeholder="自定义数值" oninput="document.getElementById('manuf-select').value = '0'">
                        </div>
                    </div>
                    <button id="btn-apply-settings" onclick="saveSettings()" class="bg-red-600 hover:bg-red-500 text-white font-bold tracking-widest text-sm py-3 rounded-xl w-full shadow-[0_0_15px_rgba(220,38,38,0.3)] hover:shadow-[0_0_25px_rgba(220,38,38,0.5)] transition-all">
                        应用设置
                    </button>
                </div>
                
                <!-- Divider -->
                <div class="hidden md:block w-px bg-gradient-to-b from-transparent via-neutral-800 to-transparent"></div>
                
                <!-- Sliders Section -->
                <div class="md:w-2/3 grid grid-cols-1 md:grid-cols-2 gap-x-10 gap-y-7">
                    <div>
                        <div class="flex justify-between items-center mb-2"><label class="text-xs font-semibold text-neutral-400">图表时间跨度</label><div class="flex items-center gap-1"><input type="number" id="limit-disp" class="bg-transparent text-right font-mono text-sm text-blue-400 font-bold w-12 outline-none border-b border-transparent focus:border-blue-500 transition m-0 p-0" oninput="snapSliderFromDisp('limit', CHART_TICKS)"><span class="text-[10px] text-neutral-500">s</span></div></div>
                        <input type="range" id="limit-input" class="w-full accent-blue-500 bg-neutral-900 rounded-full appearance-none h-2 outline-none cursor-pointer border border-neutral-800" min="0" max="8" step="1" oninput="snapSliderUpdate('limit', CHART_TICKS)">
                        <div class="tick-marks" id="limit-ticks"></div>
                    </div>
                    <div>
                        <div class="flex justify-between items-center mb-2"><label class="text-xs font-semibold text-neutral-400">渲染间隔</label><div class="flex items-center gap-1"><input type="number" id="refresh-disp" step="0.1" class="bg-transparent text-right font-mono text-sm text-emerald-400 font-bold w-12 outline-none border-b border-transparent focus:border-emerald-500 transition m-0 p-0" oninput="document.getElementById('refresh-input').value = this.value"><span class="text-[10px] text-neutral-500">s</span></div></div>
                        <input type="range" id="refresh-input" class="w-full accent-emerald-500 bg-neutral-900 rounded-full appearance-none h-2 outline-none cursor-pointer border border-neutral-800" step="0.1" min="0.1" max="10.0" oninput="document.getElementById('refresh-disp').value = this.value">
                    </div>
                    <div>
                        <div class="flex justify-between items-center mb-2"><label class="text-xs font-semibold text-neutral-400">过滤防抖缓冲</label><div class="flex items-center gap-1"><input type="number" id="filter-disp" class="bg-transparent text-right font-mono text-sm text-purple-400 font-bold w-12 outline-none border-b border-transparent focus:border-purple-500 transition m-0 p-0" oninput="document.getElementById('filter-input').value = this.value"><span class="text-[10px] text-neutral-500">ms</span></div></div>
                        <input type="range" id="filter-input" class="w-full accent-purple-500 bg-neutral-900 rounded-full appearance-none h-2 outline-none cursor-pointer border border-neutral-800" min="0" max="100" oninput="document.getElementById('filter-disp').value = this.value">
                    </div>
                    <div>
                        <div class="flex justify-between items-center mb-2"><label class="text-xs font-bold text-red-400 drop-shadow-[0_0_8px_rgba(248,113,113,0.5)]">警告心率阈值</label><div class="flex items-center gap-1"><input type="number" id="threshold-disp" class="bg-transparent text-right font-mono text-sm text-red-500 font-black w-12 outline-none border-b border-transparent focus:border-red-500 transition m-0 p-0" oninput="document.getElementById('threshold-input').value = this.value"><span class="text-[10px] text-neutral-500">BPM</span></div></div>
                        <input type="range" id="threshold-input" class="w-full accent-red-600 bg-neutral-900 rounded-full appearance-none h-2 outline-none cursor-pointer border border-red-900/30" min="50" max="250" oninput="document.getElementById('threshold-disp').value = this.value">
                    </div>
                    <div class="md:col-span-2 border-t border-neutral-800/80 pt-5 mt-[-10px]">
                        <div class="flex justify-between items-center mb-2"><label class="text-xs font-bold text-yellow-500 tracking-widest drop-shadow-[0_0_8px_rgba(234,179,8,0.2)]">数据库保存时间上限</label><div class="flex items-center gap-1"><input type="number" id="retention-disp" class="bg-transparent text-right font-mono text-sm text-yellow-400 font-bold w-12 outline-none border-b border-transparent focus:border-yellow-500 transition m-0 p-0" oninput="snapSliderFromDisp('retention', RETENTION_TICKS)"><span class="text-[10px] text-neutral-500">小时</span></div></div>
                        <input type="range" id="retention-input" class="w-full accent-yellow-600 bg-neutral-900 rounded-full appearance-none h-2 outline-none cursor-pointer border border-yellow-900/20" min="0" max="6" step="1" oninput="snapSliderUpdate('retention', RETENTION_TICKS)">
                        <div class="tick-marks" id="retention-ticks"></div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <script>
        // ========== 吸附刻度系统 ==========
        const CHART_TICKS = [60, 90, 120, 180, 300, 600, 900, 1800, 3600];
        const RETENTION_TICKS = [24, 48, 72, 96, 120, 144, 168];

        // 格式化图表时间刻度标签（秒 → 可读）
        function formatChartTick(val) {
            if (val >= 3600) return (val / 3600) + 'h';
            if (val >= 60) return (val / 60) + 'm';
            return val + 's';
        }
        // 格式化保存时间刻度标签（小时 → 可读）
        function formatRetentionTick(val) {
            if (val >= 24 && val % 24 === 0) return (val / 24) + 'd';
            return val + 'h';
        }

        // 根据滑块位置（0~N-1 整数）更新显示值
        function snapSliderUpdate(prefix, ticks) {
            const slider = document.getElementById(prefix + '-input');
            const disp = document.getElementById(prefix + '-disp');
            const idx = Math.round(parseFloat(slider.value));
            const val = ticks[Math.max(0, Math.min(idx, ticks.length - 1))];
            disp.value = val;
        }

        // 根据手动输入的数值吸附到最近刻度
        function snapSliderFromDisp(prefix, ticks) {
            const disp = document.getElementById(prefix + '-disp');
            const slider = document.getElementById(prefix + '-input');
            const raw = parseFloat(disp.value);
            if (isNaN(raw)) return;
            // 找到最近的刻度索引
            let bestIdx = 0, bestDist = Infinity;
            for (let i = 0; i < ticks.length; i++) {
                const d = Math.abs(ticks[i] - raw);
                if (d < bestDist) { bestDist = d; bestIdx = i; }
            }
            slider.value = bestIdx;
            disp.value = ticks[bestIdx];
        }

        // 设置滑块到指定数值（初始化时用）
        function setSnapSlider(prefix, ticks, value) {
            const slider = document.getElementById(prefix + '-input');
            const disp = document.getElementById(prefix + '-disp');
            let bestIdx = 0, bestDist = Infinity;
            for (let i = 0; i < ticks.length; i++) {
                const d = Math.abs(ticks[i] - value);
                if (d < bestDist) { bestDist = d; bestIdx = i; }
            }
            slider.value = bestIdx;
            disp.value = ticks[bestIdx];
        }

        // 渲染刻度标记
        function renderTickMarks(containerId, ticks, formatter) {
            const container = document.getElementById(containerId);
            container.innerHTML = '';
            const total = ticks.length - 1;
            for (let i = 0; i < ticks.length; i++) {
                const pct = (i / total) * 100;
                const tick = document.createElement('div');
                tick.className = 'tick-mark';
                tick.style.left = pct + '%';
                const label = document.createElement('span');
                label.className = 'tick-label';
                label.textContent = formatter(ticks[i]);
                tick.appendChild(label);
                container.appendChild(tick);
            }
        }

        // 初始化刻度标记
        renderTickMarks('limit-ticks', CHART_TICKS, formatChartTick);
        renderTickMarks('retention-ticks', RETENTION_TICKS, formatRetentionTick);

        const ctx = document.getElementById('hrChart').getContext('2d');
        let chartMode = 'hr'; 
        
        function setChartMode(mode) {
            chartMode = mode;
            if(mode === 'hr') {
                document.getElementById('btn-mode-hr').classList.remove('text-neutral-500');
                document.getElementById('btn-mode-hr').classList.add('text-red-500', 'font-bold');
                document.getElementById('btn-mode-rssi').classList.add('text-neutral-500');
                document.getElementById('btn-mode-rssi').classList.remove('text-blue-500', 'font-bold');
            } else {
                document.getElementById('btn-mode-rssi').classList.remove('text-neutral-500');
                document.getElementById('btn-mode-rssi').classList.add('text-blue-500', 'font-bold');
                document.getElementById('btn-mode-hr').classList.add('text-neutral-500');
                document.getElementById('btn-mode-hr').classList.remove('text-red-500', 'font-bold');
            }
            if(window.lastRenderData) renderChartData(window.lastRenderData);
        }

        const gradient = ctx.createLinearGradient(0, 0, 0, 300);
        gradient.addColorStop(0, 'rgba(239, 68, 68, 0.6)');
        gradient.addColorStop(1, 'rgba(239, 68, 68, 0.0)');

        const hrChart = new Chart(ctx, {
            type: 'line',
            data: { 
                labels: [], 
                datasets: []  // 动态生成，每个会话一个独立 dataset
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                animation: false,
                layout: { padding: { left: -10, bottom: -10 } },
                plugins: { legend: { display: false }, tooltip: { enabled: true, mode: 'index', intersect: false, filter: function(item) { return item.raw != null; } } },
                scales: {
                    y: { 
                        suggestedMin: 50, suggestedMax: 120, 
                        grid: { color: '#262626', drawBorder: false }, 
                        border: { dash: [4, 4] }, 
                        ticks: { color: '#737373', padding: 10 } 
                    },
                    x: { 
                        display: true, 
                        grid: { display: false, drawBorder: false }, 
                        ticks: { 
                            color: '#737373', 
                            maxRotation: 0,
                            autoSkip: false,
                            padding: 10,
                            callback: function(val, index) {
                                let labels = this.chart.data.labels || [];
                                let total = labels.length;
                                if (total === 0) return '';
                                let step = Math.max(1, Math.floor(total / 10)); 
                                if ((total - 1 - index) % step === 0) {
                                    return labels[index];
                                }
                                return '';
                            }
                        } 
                    }
                }
            }
        });

        let ws;
        let currentThreshold = 160;
        let hasInitializedSettings = false;
        
        function renderChartData(data) {
            window.lastRenderData = data;
            if (data.history.hr.length === 0) return;
            
            const limit = data.settings.limit;
            let hrData = data.history.hr;
            let rssiData = data.history.rssi;
            let timeData = data.history.time;
            let freshData = data.history.fresh;
            let sessionIds = data.history.session_ids || [];

            if (hrData.length < limit) {
                const padCount = limit - hrData.length;
                hrData = Array(padCount).fill(null).concat(hrData);
                rssiData = Array(padCount).fill(null).concat(rssiData);
                timeData = Array(padCount).fill('').concat(timeData);
                freshData = Array(padCount).fill(false).concat(freshData);
                sessionIds = Array(padCount).fill(null).concat(sessionIds);
            }

            hrChart.data.labels = timeData;

            // 提取唯一的非空会话 ID（保持顺序）
            const seen = new Set();
            const uniqueSessions = [];
            for (const s of sessionIds) {
                if (s != null && !seen.has(s)) {
                    seen.add(s);
                    uniqueSessions.push(s);
                }
            }

            // 为每个会话构建独立的 dataset —— 线条永远不会跨越会话边界
            const newDatasets = uniqueSessions.map(sid => {
                const segHr = hrData.map((v, i) => sessionIds[i] === sid ? v : null);
                const segRssi = rssiData.map((v, i) => sessionIds[i] === sid ? v : null);
                const segFresh = freshData.map((v, i) => sessionIds[i] === sid ? v : false);

                const segData = chartMode === 'hr' ? segHr : segRssi;
                const pointRadius = segFresh.map(f => f ? 3.5 : 0);
                let pointBgColor;
                if (chartMode === 'hr') {
                    pointBgColor = segHr.map(v => v >= currentThreshold ? '#ef4444' : '#10b981');
                } else {
                    pointBgColor = '#3b82f6';
                }

                return {
                    data: segData,
                    borderColor: '#ef4444',
                    backgroundColor: gradient,
                    borderWidth: 2,
                    fill: true,
                    pointRadius: pointRadius,
                    pointBackgroundColor: pointBgColor,
                    pointBorderColor: '#050505',
                    pointBorderWidth: 1.5,
                    tension: 0.5,
                    cubicInterpolationMode: 'monotone',
                    spanGaps: true
                };
            });

            hrChart.data.datasets = newDatasets;

            // 应用基于阈值的渐变颜色
            if (chartMode === 'hr') {
                hrChart.options.scales.y.suggestedMin = 50;
                hrChart.options.scales.y.suggestedMax = 120;

                const yArea = hrChart.scales.y;
                if (yArea && yArea.bottom) {
                    const yPixelThreshold = yArea.getPixelForValue(currentThreshold);
                    const stopPct = (yPixelThreshold - yArea.top) / (yArea.bottom - yArea.top);
                    const safeStop = Math.max(0, Math.min(1, stopPct));

                    const gradientLine = ctx.createLinearGradient(0, yArea.top, 0, yArea.bottom);
                    gradientLine.addColorStop(0, '#ef4444');
                    gradientLine.addColorStop(safeStop, '#ef4444');
                    gradientLine.addColorStop(safeStop, '#10b981');
                    gradientLine.addColorStop(1, '#10b981');

                    const bgGradient = ctx.createLinearGradient(0, yArea.top, 0, yArea.bottom);
                    bgGradient.addColorStop(0, 'rgba(239, 68, 68, 0.4)');
                    bgGradient.addColorStop(safeStop, 'rgba(239, 68, 68, 0.05)');
                    bgGradient.addColorStop(safeStop, 'rgba(16, 185, 129, 0.4)');
                    bgGradient.addColorStop(1, 'rgba(16, 185, 129, 0.05)');

                    for (const ds of hrChart.data.datasets) {
                        ds.borderColor = gradientLine;
                        ds.backgroundColor = bgGradient;
                    }
                }
            } else {
                hrChart.options.scales.y.suggestedMin = -100;
                hrChart.options.scales.y.suggestedMax = -40;

                const yArea = hrChart.scales.y;
                if (yArea && yArea.bottom) {
                    const gradientLine = ctx.createLinearGradient(0, yArea.top, 0, yArea.bottom);
                    gradientLine.addColorStop(0, '#3b82f6');
                    gradientLine.addColorStop(1, '#60a5fa');

                    const bgGradient = ctx.createLinearGradient(0, yArea.top, 0, yArea.bottom);
                    bgGradient.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
                    bgGradient.addColorStop(1, 'rgba(59, 130, 246, 0.05)');

                    for (const ds of hrChart.data.datasets) {
                        ds.borderColor = gradientLine;
                        ds.backgroundColor = bgGradient;
                    }
                }
            }

            hrChart.update('none');
        }

        function connect() {
            ws = new WebSocket(`ws://${window.location.host}/ws`);
            
            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                
                const dot = document.getElementById('status-dot');
                const statusText = document.getElementById('status-text');
                
                if(!data.stats.is_scanning) {
                    dot.innerHTML = '<span class="relative h-2.5 w-2.5 rounded-full bg-yellow-400 shadow-[0_0_8px_rgba(250,204,21,0.8)]"></span>';
                    statusText.innerText = 'PAUSED / OFF';
                    statusText.className = 'text-sm font-bold text-yellow-400 tracking-wider group-hover/btn:opacity-80 transition';
                } else if(statusText.innerText === 'PAUSED / OFF') {
                    dot.innerHTML = '<span class="animate-ping absolute h-full w-full rounded-full bg-emerald-500 opacity-75"></span><span class="relative h-2.5 w-2.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]"></span>';
                    statusText.innerText = 'CONNECTED';
                    statusText.className = 'text-sm font-bold text-emerald-400 tracking-wider group-hover/btn:opacity-80 transition';
                }

                if(!hasInitializedSettings) {
                    document.getElementById('mac-input').value = data.settings.mac;
                    document.getElementById('manuf-input').value = data.settings.manuf_id || 343;
                    const selectEl = document.getElementById('manuf-select');
                    let exists = Array.from(selectEl.options).some(opt => opt.value == (data.settings.manuf_id || 343));
                    selectEl.value = exists ? (data.settings.manuf_id || 343) : '0';
                    document.getElementById('filter-input').value = data.settings.filter;
                    document.getElementById('filter-disp').value = data.settings.filter;
                    document.getElementById('refresh-input').value = data.settings.refresh;
                    document.getElementById('refresh-disp').value = parseFloat(data.settings.refresh).toFixed(1);
                    setSnapSlider('limit', CHART_TICKS, data.settings.duration);
                    document.getElementById('threshold-input').value = data.settings.threshold;
                    document.getElementById('threshold-disp').value = data.settings.threshold;
                    if (data.settings.retention) {
                        setSnapSlider('retention', RETENTION_TICKS, data.settings.retention);
                    }
                    hasInitializedSettings = true;
                }
                
                currentThreshold = data.settings.threshold;

                const hrEl = document.getElementById('hr-value');
                const hrGlow = document.getElementById('hr-glow-bg');
                hrEl.innerText = data.stats.hr || '--';
                
                if (data.stats.hr > 0) {
                    if (!hrGlow.classList.contains('pulsing-glow')) {
                        hrGlow.classList.add('pulsing-glow');
                        hrGlow.classList.remove('opacity-0');
                    }
                    hrGlow.style.animationDuration = (60 / data.stats.hr).toFixed(3) + 's';
                } else {
                    hrGlow.classList.add('opacity-0');
                    hrGlow.classList.remove('pulsing-glow');
                }

                if(data.stats.hr >= currentThreshold) {
                    hrEl.classList.add('text-red-500'); hrEl.classList.remove('text-white');
                    hrGlow.classList.add('bg-red-600/50'); hrGlow.classList.remove('bg-red-500/20');
                } else {
                    hrEl.classList.remove('text-red-500'); hrEl.classList.add('text-white');
                    hrGlow.classList.add('bg-red-500/20'); hrGlow.classList.remove('bg-red-600/50');
                }

                document.getElementById('device-name').innerText = data.stats.name;
                document.getElementById('manuf-badge').innerText = data.settings.manuf_id || '343';
                document.getElementById('raw-data').innerText = data.stats.raw || '等待数据...';
                document.getElementById('update-time').innerText = '上次更新: ' + data.stats.time;
                document.getElementById('time-since-last').innerText = data.stats.time_since_last_display;
                document.getElementById('avg-interval').innerText = data.stats.avg_interval_ms;
                document.getElementById('avg-hz-val').innerText = data.stats.avg_hz > 0 ? data.stats.avg_hz.toFixed(2) : '--';
                if(document.getElementById('session-time-val')) {
                    document.getElementById('session-time-val').innerText = data.stats.session_time_text;
                }
                
                const rssi = data.stats.rssi;
                const rssiBar = document.getElementById('rssi-bar');
                if (rssi === "--" || rssi === null || rssi === undefined) {
                    document.getElementById('rssi-value').innerText = '-- dBm';
                    rssiBar.style.width = '0%';
                    rssiBar.className = 'h-full bg-neutral-700 transition-all duration-300';
                } else {
                    document.getElementById('rssi-value').innerText = rssi + ' dBm';
                    let rssiPercent = Math.max(0, Math.min(100, (rssi + 100) * (100 / 60)));
                    rssiBar.style.width = rssiPercent + '%';
                    if(rssiPercent > 70) rssiBar.className = 'h-full bg-emerald-500 transition-all duration-300 shadow-[0_0_10px_rgba(16,185,129,0.8)]';
                    else if(rssiPercent > 30) rssiBar.className = 'h-full bg-yellow-500 transition-all duration-300';
                    else rssiBar.className = 'h-full bg-red-500 transition-all duration-300 shadow-[0_0_10px_rgba(239,68,68,0.8)]';
                }

                // Chart 数据更新渲染逻辑
                renderChartData(data);
            };

            ws.onclose = function() {
                const dot = document.getElementById('status-dot');
                dot.innerHTML = '<span class="relative h-2.5 w-2.5 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]"></span>';
                document.getElementById('status-text').innerText = 'LINK LOST ...';
                document.getElementById('status-text').className = 'text-sm font-bold text-red-500 tracking-wider group-hover/btn:opacity-80 transition';
                hasInitializedSettings = false; 
                setTimeout(connect, 2000);
            };

            ws.onopen = function() {
                const dot = document.getElementById('status-dot');
                dot.innerHTML = '<span class="animate-ping absolute h-full w-full rounded-full bg-emerald-500 opacity-75"></span><span class="relative h-2.5 w-2.5 rounded-full bg-emerald-500 shadow-[0_0_8px_rgba(16,185,129,0.8)]"></span>';
                document.getElementById('status-text').innerText = 'CONNECTED';
                document.getElementById('status-text').className = 'text-sm font-bold text-emerald-400 tracking-wider group-hover/btn:opacity-80 transition';
            };
        }

        async function toggleScan() {
            await fetch('/api/toggle_scan', { method: 'POST' });
        }

        async function saveSettings() {
            const payload = {
                mac: document.getElementById('mac-input').value,
                manuf_id: parseInt(document.getElementById('manuf-input').value) || 343,
                filter: parseInt(document.getElementById('filter-disp').value) || 10,
                refresh: parseFloat(document.getElementById('refresh-disp').value) || 1.0,
                duration: parseInt(document.getElementById('limit-disp').value) || 300,
                threshold: parseInt(document.getElementById('threshold-disp').value) || 160,
                retention: parseInt(document.getElementById('retention-disp').value) || 72
            };
            
            await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            
            const btn = document.getElementById('btn-apply-settings');
            const oldText = btn.innerText;
            btn.innerText = '已应用 ✔️';
            btn.classList.add('bg-emerald-600', 'text-white', 'shadow-[0_0_15px_rgba(16,185,129,0.5)]');
            btn.classList.remove('bg-red-600', 'text-white', 'shadow-[0_0_15px_rgba(220,38,38,0.3)]');
            setTimeout(() => {
                btn.innerText = oldText;
                btn.classList.remove('bg-emerald-600', 'text-white', 'shadow-[0_0_15px_rgba(16,185,129,0.5)]');
                btn.classList.add('bg-red-600', 'text-white', 'shadow-[0_0_15px_rgba(220,38,38,0.3)]');
            }, 2000);
        }

        connect();
    </script>
</body>
</html>
"""

# ================= 前端模板：蓝牙设备扫描探测器 =================
HTML_SCAN = """
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BLE 设备扫描探测器</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        body { background-color: #050505; color: #e5e5e5; }
        .glass { background: rgba(15, 15, 15, 0.7); backdrop-filter: blur(16px); border: 1px solid #262626; box-shadow: inset 0 1px 0 rgba(255,255,255,0.05); }
        input[type="text"], input[type="search"] { background: #171717; border: 1px solid #404040; color: #e5e5e5; outline: none; transition: border 0.2s; }
        input[type="text"]:focus, input[type="search"]:focus { border-color: #6366f1; }

        /* 自定义滚动条 */
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0a0a0a; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }
        ::-webkit-scrollbar-thumb:hover { background: #555; }

        /* 设备行动画 */
        .device-row { transition: all 0.3s ease; }
        .device-row:hover { background: rgba(99, 102, 241, 0.08) !important; }
        .device-row.new-flash { animation: flash-in 1s ease-out; }
        @keyframes flash-in {
            0% { background: rgba(99, 102, 241, 0.3); }
            100% { background: transparent; }
        }

        /* 信号强度条 */
        .rssi-bar-bg { background: #1a1a1a; }
        .rssi-bar-fill { transition: width 0.5s ease, background 0.5s ease; }

        /* 展开详情面板 */
        .detail-panel { max-height: 0; overflow: hidden; transition: max-height 0.4s cubic-bezier(0.4, 0, 0.2, 1), opacity 0.3s ease; opacity: 0; }
        .detail-panel.open { max-height: 800px; opacity: 1; }

        /* 数据标签 */
        .data-tag { font-size: 10px; padding: 2px 6px; border-radius: 4px; font-family: monospace; display: inline-block; margin: 1px; }
        .tag-manuf { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.2); }
        .tag-service { background: rgba(59, 130, 246, 0.15); color: #93c5fd; border: 1px solid rgba(59, 130, 246, 0.2); }
        .tag-uuid { background: rgba(16, 185, 129, 0.15); color: #6ee7b7; border: 1px solid rgba(16, 185, 129, 0.2); }

        /* 脉冲扫描指示器 */
        @keyframes scan-pulse {
            0% { transform: scale(1); opacity: 1; }
            50% { transform: scale(1.8); opacity: 0; }
            100% { transform: scale(1); opacity: 0; }
        }
        .scan-ring { animation: scan-pulse 2s infinite ease-out; }

        /* 排序箭头 */
        .sort-btn { cursor: pointer; user-select: none; }
        .sort-btn:hover { color: #a5b4fc; }
        .sort-active { color: #818cf8 !important; }

        /* 复制按钮 */
        .copy-btn { opacity: 0; transition: opacity 0.2s; }
        .device-row:hover .copy-btn { opacity: 1; }

        /* 统计卡片微光 */
        .stat-glow { position: absolute; width: 80px; height: 80px; border-radius: 50%; filter: blur(30px); pointer-events: none; transition: opacity 0.5s; }
    </style>
</head>
<body class="p-4 md:p-8 min-h-screen font-sans flex justify-center">
    <div class="max-w-7xl w-full space-y-6">

        <!-- HEADER -->
        <div class="glass flex justify-between items-center rounded-2xl p-6 shadow-2xl relative overflow-hidden group">
            <div class="absolute inset-x-0 -top-10 h-20 bg-indigo-600/10 blur-2xl pointer-events-none transition duration-500 group-hover:bg-indigo-600/20"></div>
            <div class="relative z-10">
                <h1 class="text-2xl md:text-3xl font-black text-white tracking-widest uppercase">BLE 设备扫描探测器</h1>
                <p class="text-xs text-neutral-500 mt-2 font-mono">发现附近所有蓝牙广播设备 · 完整原始数据查看 · <a href="/" class="text-neutral-400 hover:text-white transition bg-neutral-900 px-2 py-0.5 rounded cursor-pointer">← 返回仪表盘</a></p>
            </div>
            <div class="flex items-center gap-4 relative z-10">
                <!-- 扫描状态指示 -->
                <div class="flex items-center gap-3">
                    <div class="relative flex h-3 w-3">
                        <span class="scan-ring absolute h-full w-full rounded-full bg-indigo-500 opacity-75" id="scan-ring"></span>
                        <span class="relative h-3 w-3 rounded-full bg-indigo-500 shadow-[0_0_10px_rgba(99,102,241,0.8)]" id="scan-dot"></span>
                    </div>
                    <span id="scan-status-text" class="text-sm font-bold text-indigo-400 tracking-wider">扫描中...</span>
                </div>
                <button onclick="clearDevices()" class="px-4 py-2 rounded-xl bg-neutral-900 border border-neutral-800 hover:border-red-800 text-neutral-400 hover:text-red-400 text-xs font-bold tracking-wider transition cursor-pointer">清空列表</button>
            </div>
        </div>

        <!-- 统计概览 -->
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div class="glass rounded-2xl p-5 relative overflow-hidden">
                <div class="stat-glow top-0 right-0 bg-indigo-500/20"></div>
                <div class="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-1">发现设备</div>
                <div class="text-3xl font-black text-white font-mono" id="stat-total">0</div>
            </div>
            <div class="glass rounded-2xl p-5 relative overflow-hidden">
                <div class="stat-glow top-0 right-0 bg-emerald-500/20"></div>
                <div class="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-1">有名称设备</div>
                <div class="text-3xl font-black text-emerald-400 font-mono" id="stat-named">0</div>
            </div>
            <div class="glass rounded-2xl p-5 relative overflow-hidden">
                <div class="stat-glow top-0 right-0 bg-purple-500/20"></div>
                <div class="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-1">有制造商数据</div>
                <div class="text-3xl font-black text-purple-400 font-mono" id="stat-manuf">0</div>
            </div>
            <div class="glass rounded-2xl p-5 relative overflow-hidden">
                <div class="stat-glow top-0 right-0 bg-blue-500/20"></div>
                <div class="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-1">累计广播包</div>
                <div class="text-3xl font-black text-blue-400 font-mono" id="stat-packets">0</div>
            </div>
        </div>

        <!-- 搜索与过滤 -->
        <div class="glass rounded-2xl p-4 flex flex-col md:flex-row gap-4 items-center">
            <div class="relative flex-1 w-full">
                <input type="search" id="search-input" placeholder="搜索设备名称、MAC 地址、UUID..." class="w-full px-4 py-3 rounded-xl text-sm font-mono pl-10" oninput="applyFilters()">
                <svg class="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-neutral-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
            </div>
            <div class="flex gap-2 flex-wrap">
                <button onclick="toggleFilter('named')" id="filter-named" class="px-3 py-2 rounded-lg text-[11px] font-bold tracking-wider border border-neutral-800 bg-neutral-900 text-neutral-500 hover:border-emerald-800 hover:text-emerald-400 transition cursor-pointer">仅有名称</button>
                <button onclick="toggleFilter('manuf')" id="filter-manuf" class="px-3 py-2 rounded-lg text-[11px] font-bold tracking-wider border border-neutral-800 bg-neutral-900 text-neutral-500 hover:border-purple-800 hover:text-purple-400 transition cursor-pointer">有制造商数据</button>
                <button onclick="toggleFilter('strong')" id="filter-strong" class="px-3 py-2 rounded-lg text-[11px] font-bold tracking-wider border border-neutral-800 bg-neutral-900 text-neutral-500 hover:border-blue-800 hover:text-blue-400 transition cursor-pointer">强信号 (≥-70)</button>
                <select id="sort-select" onchange="applyFilters()" class="px-3 py-2 rounded-lg text-[11px] font-bold tracking-wider border border-neutral-800 bg-neutral-900 text-neutral-400 outline-none cursor-pointer">
                    <option value="rssi">按信号强度排序 ↓</option>
                    <option value="name">按名称排序 A→Z</option>
                    <option value="mac">按 MAC 排序</option>
                    <option value="recent">按最近发现排序</option>
                    <option value="hits">按广播次数排序 ↓</option>
                </select>
            </div>
        </div>

        <!-- 设备列表 -->
        <div class="glass rounded-2xl overflow-hidden">
            <!-- 表头 -->
            <div class="grid grid-cols-12 gap-2 px-6 py-3 text-[10px] font-bold text-neutral-600 uppercase tracking-widest border-b border-neutral-800/50 bg-black/30">
                <div class="col-span-1">信号</div>
                <div class="col-span-2">MAC 地址</div>
                <div class="col-span-3">设备名称</div>
                <div class="col-span-2">制造商数据</div>
                <div class="col-span-1">广播次数</div>
                <div class="col-span-2">最后发现</div>
                <div class="col-span-1">操作</div>
            </div>
            <!-- 设备行列表容器 -->
            <div id="device-list" class="max-h-[60vh] overflow-y-auto">
                <div class="text-center py-20 text-neutral-600">
                    <div class="text-4xl mb-4">📡</div>
                    <div class="text-sm font-mono">正在扫描附近蓝牙设备...</div>
                </div>
            </div>
        </div>

        <!-- 底部信息 -->
        <div class="text-center text-[10px] text-neutral-700 font-mono py-2">
            扫描数据每 1 秒自动刷新 · 点击设备行查看完整广播数据
        </div>
    </div>

    <!-- 复制成功提示 -->
    <div id="copy-toast" class="fixed bottom-6 right-6 bg-emerald-600 text-white px-4 py-2 rounded-xl text-sm font-bold shadow-[0_0_20px_rgba(16,185,129,0.4)] transition-all duration-300 opacity-0 translate-y-4 pointer-events-none z-50">
        ✓ 已复制到剪贴板
    </div>

    <script>
        let allDevices = {};
        let activeFilters = new Set();
        let expandedMac = null;
        let ws;

        // ========== WebSocket 连接 ==========
        function connect() {
            ws = new WebSocket(`ws://${window.location.host}/ws/scan`);

            ws.onmessage = function(event) {
                const data = JSON.parse(event.data);
                allDevices = data.devices || {};
                updateStats(data);
                renderDeviceList();
            };

            ws.onclose = function() {
                document.getElementById('scan-status-text').innerText = '连接断开...';
                document.getElementById('scan-dot').className = 'relative h-3 w-3 rounded-full bg-red-500 shadow-[0_0_10px_rgba(239,68,68,0.8)]';
                document.getElementById('scan-ring').style.display = 'none';
                setTimeout(connect, 2000);
            };

            ws.onopen = function() {
                document.getElementById('scan-status-text').innerText = '扫描中...';
                document.getElementById('scan-dot').className = 'relative h-3 w-3 rounded-full bg-indigo-500 shadow-[0_0_10px_rgba(99,102,241,0.8)]';
                document.getElementById('scan-ring').style.display = 'block';
            };
        }

        // ========== 统计更新 ==========
        function updateStats(data) {
            const devices = Object.values(allDevices);
            document.getElementById('stat-total').innerText = devices.length;
            document.getElementById('stat-named').innerText = devices.filter(d => d.name && d.name.length > 0).length;
            document.getElementById('stat-manuf').innerText = devices.filter(d => Object.keys(d.manufacturer_data || {}).length > 0).length;

            let totalHits = 0;
            for (const d of devices) totalHits += d.hit_count || 0;
            document.getElementById('stat-packets').innerText = totalHits;
        }

        // ========== 过滤与排序 ==========
        function toggleFilter(name) {
            const btn = document.getElementById('filter-' + name);
            if (activeFilters.has(name)) {
                activeFilters.delete(name);
                btn.classList.remove('border-indigo-600', 'text-indigo-400', 'bg-indigo-950/50');
                btn.classList.add('border-neutral-800', 'text-neutral-500', 'bg-neutral-900');
            } else {
                activeFilters.add(name);
                btn.classList.add('border-indigo-600', 'text-indigo-400', 'bg-indigo-950/50');
                btn.classList.remove('border-neutral-800', 'text-neutral-500', 'bg-neutral-900');
            }
            renderDeviceList();
        }

        function applyFilters() {
            renderDeviceList();
        }

        function getFilteredDevices() {
            let devices = Object.values(allDevices);
            const query = (document.getElementById('search-input').value || '').toLowerCase();

            // 文本搜索
            if (query) {
                devices = devices.filter(d => {
                    const searchStr = [
                        d.name, d.mac,
                        ...Object.keys(d.manufacturer_data || {}),
                        ...Object.values(d.manufacturer_data || {}).map(v => v.hex || ''),
                        ...(d.service_uuids || []),
                        ...Object.keys(d.service_data || {}),
                        ...Object.values(d.service_data || {}).map(v => v.hex || '')
                    ].join(' ').toLowerCase();
                    return searchStr.includes(query);
                });
            }

            // 按钮过滤
            if (activeFilters.has('named')) devices = devices.filter(d => d.name && d.name.length > 0);
            if (activeFilters.has('manuf')) devices = devices.filter(d => Object.keys(d.manufacturer_data || {}).length > 0);
            if (activeFilters.has('strong')) devices = devices.filter(d => d.rssi >= -70);

            // 排序
            const sort = document.getElementById('sort-select').value;
            switch (sort) {
                case 'rssi': devices.sort((a, b) => b.rssi - a.rssi); break;
                case 'name': devices.sort((a, b) => (a.name || 'zzz').localeCompare(b.name || 'zzz')); break;
                case 'mac': devices.sort((a, b) => a.mac.localeCompare(b.mac)); break;
                case 'recent': devices.sort((a, b) => b.last_seen_ms - a.last_seen_ms); break;
                case 'hits': devices.sort((a, b) => (b.hit_count || 0) - (a.hit_count || 0)); break;
            }

            return devices;
        }

        // ========== 渲染设备列表 ==========
        function renderDeviceList() {
            const container = document.getElementById('device-list');
            const devices = getFilteredDevices();

            if (devices.length === 0) {
                container.innerHTML = `<div class="text-center py-20 text-neutral-600">
                    <div class="text-4xl mb-4">📡</div>
                    <div class="text-sm font-mono">${Object.keys(allDevices).length === 0 ? '正在扫描附近蓝牙设备...' : '没有匹配的设备'}</div>
                </div>`;
                return;
            }

            let html = '';
            for (const d of devices) {
                const rssiPct = Math.max(0, Math.min(100, (d.rssi + 100) * (100 / 60)));
                let rssiColor, rssiTextColor;
                if (rssiPct > 70) { rssiColor = '#10b981'; rssiTextColor = 'text-emerald-400'; }
                else if (rssiPct > 40) { rssiColor = '#eab308'; rssiTextColor = 'text-yellow-400'; }
                else { rssiColor = '#ef4444'; rssiTextColor = 'text-red-400'; }

                const hasManuf = Object.keys(d.manufacturer_data || {}).length > 0;
                const manufSummary = hasManuf
                    ? Object.entries(d.manufacturer_data).map(([id, v]) => `<span class="data-tag tag-manuf">ID:${id} (${v.length}B)</span>`).join('')
                    : '<span class="text-neutral-700 text-[10px]">无</span>';

                const isExpanded = expandedMac === d.mac;

                html += `
                <div class="device-row border-b border-neutral-900/50" data-mac="${d.mac}">
                    <div class="grid grid-cols-12 gap-2 px-6 py-3 items-center cursor-pointer hover:bg-neutral-900/30" onclick="toggleDetail('${d.mac}')">
                        <div class="col-span-1">
                            <div class="flex flex-col gap-1">
                                <span class="font-mono text-xs font-bold ${rssiTextColor}">${d.rssi}</span>
                                <div class="rssi-bar-bg rounded-full h-1.5 w-full">
                                    <div class="rssi-bar-fill h-full rounded-full" style="width:${rssiPct}%;background:${rssiColor}"></div>
                                </div>
                            </div>
                        </div>
                        <div class="col-span-2">
                            <span class="font-mono text-[11px] text-indigo-300 tracking-wide">${d.mac}</span>
                        </div>
                        <div class="col-span-3">
                            <span class="text-sm ${d.name ? 'text-white font-semibold' : 'text-neutral-600 italic'}">${d.name || '未知设备'}</span>
                        </div>
                        <div class="col-span-2">${manufSummary}</div>
                        <div class="col-span-1">
                            <span class="font-mono text-xs text-neutral-400">${d.hit_count || 0}</span>
                        </div>
                        <div class="col-span-2">
                            <span class="font-mono text-[11px] text-neutral-500">${d.last_seen_text}</span>
                        </div>
                        <div class="col-span-1 flex gap-1">
                            <button onclick="event.stopPropagation();copyText('${d.mac}')" class="copy-btn px-2 py-1 rounded bg-neutral-900 border border-neutral-800 text-[10px] text-neutral-400 hover:text-indigo-400 hover:border-indigo-800 transition" title="复制 MAC">MAC</button>
                            <button onclick="event.stopPropagation();useMac('${d.mac}')" class="copy-btn px-2 py-1 rounded bg-neutral-900 border border-neutral-800 text-[10px] text-neutral-400 hover:text-emerald-400 hover:border-emerald-800 transition" title="设为监听目标">选用</button>
                        </div>
                    </div>

                    <!-- 展开详情面板 -->
                    <div class="detail-panel ${isExpanded ? 'open' : ''}" id="detail-${d.mac.replace(/:/g, '')}">
                        <div class="px-6 pb-4 pt-1 border-t border-neutral-800/30">
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                <!-- 基础信息 -->
                                <div class="bg-black/40 rounded-xl p-4 border border-neutral-800/50">
                                    <div class="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-3">基础信息</div>
                                    <div class="space-y-2 text-[11px] font-mono">
                                        <div class="flex justify-between"><span class="text-neutral-500">MAC 地址</span><span class="text-indigo-300">${d.mac}</span></div>
                                        <div class="flex justify-between"><span class="text-neutral-500">设备名称</span><span class="text-white">${d.name || '(空)'}</span></div>
                                        <div class="flex justify-between"><span class="text-neutral-500">RSSI 信号</span><span class="${rssiTextColor}">${d.rssi} dBm</span></div>
                                        <div class="flex justify-between"><span class="text-neutral-500">TX Power</span><span class="text-neutral-300">${d.tx_power !== null && d.tx_power !== undefined ? d.tx_power + ' dBm' : '(未报告)'}</span></div>
                                        <div class="flex justify-between"><span class="text-neutral-500">首次发现</span><span class="text-neutral-400">${d.first_seen_text || '--'}</span></div>
                                        <div class="flex justify-between"><span class="text-neutral-500">最后发现</span><span class="text-neutral-400">${d.last_seen_text}</span></div>
                                        <div class="flex justify-between"><span class="text-neutral-500">累计包数</span><span class="text-blue-400">${d.hit_count || 0}</span></div>
                                    </div>
                                </div>

                                <!-- 制造商数据 -->
                                <div class="bg-black/40 rounded-xl p-4 border border-neutral-800/50">
                                    <div class="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-3">制造商数据 (Manufacturer Data)</div>
                                    ${renderManufDetail(d.manufacturer_data)}
                                </div>

                                <!-- 服务 UUID -->
                                <div class="bg-black/40 rounded-xl p-4 border border-neutral-800/50">
                                    <div class="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-3">服务 UUID (Service UUIDs)</div>
                                    ${renderServiceUuids(d.service_uuids)}
                                </div>

                                <!-- 服务数据 -->
                                <div class="bg-black/40 rounded-xl p-4 border border-neutral-800/50">
                                    <div class="text-[10px] text-neutral-500 font-bold uppercase tracking-widest mb-3">服务数据 (Service Data)</div>
                                    ${renderServiceData(d.service_data)}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>`;
            }

            container.innerHTML = html;
        }

        // ========== 详情渲染辅助函数 ==========
        function renderManufDetail(manufData) {
            if (!manufData || Object.keys(manufData).length === 0) {
                return '<div class="text-neutral-700 text-[11px] font-mono">此设备未广播制造商数据</div>';
            }
            let html = '';
            for (const [id, data] of Object.entries(manufData)) {
                html += `<div class="mb-3 last:mb-0">
                    <div class="flex items-center gap-2 mb-1">
                        <span class="data-tag tag-manuf">ID: ${id} (0x${parseInt(id).toString(16).toUpperCase().padStart(4,'0')})</span>
                        <span class="text-[10px] text-neutral-600">${data.length} bytes</span>
                        <button onclick="event.stopPropagation();copyText('${data.hex}')" class="text-[9px] text-neutral-600 hover:text-purple-400 transition cursor-pointer">[复制]</button>
                    </div>
                    <div class="bg-neutral-950 rounded p-2 font-mono text-[11px] text-purple-300 break-all border border-neutral-800/50">
                        HEX: ${formatHex(data.hex)}
                    </div>
                    <div class="bg-neutral-950 rounded p-2 font-mono text-[10px] text-neutral-500 break-all border border-neutral-800/50 mt-1">
                        DEC: [${(data.bytes || []).join(', ')}]
                    </div>
                </div>`;
            }
            return html;
        }

        function renderServiceUuids(uuids) {
            if (!uuids || uuids.length === 0) {
                return '<div class="text-neutral-700 text-[11px] font-mono">无服务 UUID</div>';
            }
            return uuids.map(u => `<div class="mb-1"><span class="data-tag tag-uuid">${u}</span></div>`).join('');
        }

        function renderServiceData(serviceData) {
            if (!serviceData || Object.keys(serviceData).length === 0) {
                return '<div class="text-neutral-700 text-[11px] font-mono">此设备未广播服务数据</div>';
            }
            let html = '';
            for (const [uuid, data] of Object.entries(serviceData)) {
                html += `<div class="mb-3 last:mb-0">
                    <div class="flex items-center gap-2 mb-1">
                        <span class="data-tag tag-service">${uuid}</span>
                        <span class="text-[10px] text-neutral-600">${data.length} bytes</span>
                        <button onclick="event.stopPropagation();copyText('${data.hex}')" class="text-[9px] text-neutral-600 hover:text-blue-400 transition cursor-pointer">[复制]</button>
                    </div>
                    <div class="bg-neutral-950 rounded p-2 font-mono text-[11px] text-blue-300 break-all border border-neutral-800/50">
                        HEX: ${formatHex(data.hex)}
                    </div>
                    <div class="bg-neutral-950 rounded p-2 font-mono text-[10px] text-neutral-500 break-all border border-neutral-800/50 mt-1">
                        DEC: [${(data.bytes || []).join(', ')}]
                    </div>
                </div>`;
            }
            return html;
        }

        function formatHex(hex) {
            if (!hex) return '';
            return hex.match(/.{1,2}/g).join(' ');
        }

        // ========== 交互操作 ==========
        function toggleDetail(mac) {
            const cleanMac = mac.replace(/:/g, '');
            const panel = document.getElementById('detail-' + cleanMac);
            if (expandedMac === mac) {
                panel.classList.remove('open');
                expandedMac = null;
            } else {
                // 关闭之前的
                if (expandedMac) {
                    const prevPanel = document.getElementById('detail-' + expandedMac.replace(/:/g, ''));
                    if (prevPanel) prevPanel.classList.remove('open');
                }
                panel.classList.add('open');
                expandedMac = mac;
            }
        }

        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                const toast = document.getElementById('copy-toast');
                toast.classList.remove('opacity-0', 'translate-y-4');
                toast.classList.add('opacity-100', 'translate-y-0');
                setTimeout(() => {
                    toast.classList.add('opacity-0', 'translate-y-4');
                    toast.classList.remove('opacity-100', 'translate-y-0');
                }, 1500);
            });
        }

        async function useMac(mac) {
            await fetch('/api/settings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ mac: mac })
            });
            const toast = document.getElementById('copy-toast');
            toast.innerText = '✓ 已设为监听目标: ' + mac;
            toast.classList.remove('opacity-0', 'translate-y-4');
            toast.classList.add('opacity-100', 'translate-y-0');
            setTimeout(() => {
                toast.innerText = '✓ 已复制到剪贴板';
                toast.classList.add('opacity-0', 'translate-y-4');
                toast.classList.remove('opacity-100', 'translate-y-0');
            }, 2000);
        }

        async function clearDevices() {
            await fetch('/api/scan/clear', { method: 'POST' });
            allDevices = {};
            renderDeviceList();
        }

        // 启动
        connect();
    </script>
</body>
</html>
"""

@app.get("/")
async def get_dashboard():
    return HTMLResponse(HTML_DASHBOARD)

@app.get("/live")
async def get_live_overlay():
    return HTMLResponse(HTML_LIVE)

@app.get("/scan")
async def get_scan_page():
    """蓝牙设备扫描探测器页面"""
    return HTMLResponse(HTML_SCAN)

@app.post("/api/toggle_scan")
async def toggle_scan():
    if state.is_scanning:
        if state.scanner:
            try:
                await state.scanner.stop()
            except Exception:
                pass
        # 关闭当前扫描会话
        if state.current_session_id is not None:
            end_ms = int(time.time() * 1000)
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute('UPDATE scan_sessions SET end_ms = ? WHERE id = ?', (end_ms, state.current_session_id))
            conn.commit()
            conn.close()
            print(f"📋 会话 #{state.current_session_id} 已关闭")
            state.current_session_id = None
        state.is_scanning = False
        return {"status": "success", "is_scanning": False}
    else:
        if not state.scanner:
            state.scanner = BleakScanner(detection_callback)
        await state.scanner.start()
        state.is_scanning = True
        state.session_start_time = int(time.time() * 1000)
        state.session_packet_count = 0
        # 创建新的扫描会话
        now_ms = int(time.time() * 1000)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('INSERT INTO scan_sessions (start_ms) VALUES (?)', (now_ms,))
        state.current_session_id = c.lastrowid
        conn.commit()
        conn.close()
        print(f"📋 会话 #{state.current_session_id} 已创建")
        return {"status": "success", "is_scanning": True}

@app.post("/api/settings")
async def update_settings(request: Request):
    try:
        data = await request.json()
        if "mac" in data:
            state.save_setting('target_mac', str(data["mac"]))
        if "manuf_id" in data:
            state.save_setting('manuf_id', int(data["manuf_id"]))
        if "filter" in data:
            state.save_setting('duplicate_filter_ms', max(0, min(100, int(data["filter"]))))
        if "refresh" in data:
            state.save_setting('chart_refresh_interval', max(0.1, min(10.0, float(data["refresh"]))))
        if "duration" in data:
            state.save_setting('chart_duration_s', max(10, min(3600, int(data["duration"]))))
        if "threshold" in data:
            state.save_setting('hr_threshold', int(data["threshold"]))
        if "retention" in data:
            state.save_setting('retention_hours', max(1, min(168, int(data["retention"]))))
            
        return {"status": "success"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/api/scan/clear")
async def clear_scan_devices():
    """清空扫描发现的设备列表"""
    state.scan_devices.clear()
    state.scan_device_count = 0
    return {"status": "success"}

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    state.connected_websockets.append(websocket)
    await broadcast_update()
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        state.connected_websockets.remove(websocket)

@app.websocket("/ws/scan")
async def websocket_scan_endpoint(websocket: WebSocket):
    """扫描页面专用 WebSocket：定时推送所有发现的设备数据"""
    await websocket.accept()
    state.scan_websockets.append(websocket)
    # 立即发送一次当前数据
    try:
        await websocket.send_text(json.dumps({
            "devices": state.scan_devices,
            "is_scanning": state.is_scanning,
            "total": state.scan_device_count
        }))
    except Exception:
        pass
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in state.scan_websockets:
            state.scan_websockets.remove(websocket)

if __name__ == "__main__":
    print("===================================================")
    print(" 🚀 BLE 实时心率展示系统启动成功！")
    print(" 🖥️  主控仪表盘页面: http://127.0.0.1:8000")
    print(" 🎥  OBS 源接入口: http://127.0.0.1:8000/live")
    print(" 📡 蓝牙扫描探测器: http://127.0.0.1:8000/scan")
    print("===================================================\\n")
    uvicorn.run(app, host="0.0.0.0", port=8000, access_log=False)