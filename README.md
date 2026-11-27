# Wireshark_Package_Tool（本地端封包示波器）

基於 Python 3 標準函式庫與 Wireshark CLI（`tshark`、`capinfos`）的本地端網頁封包分析工具，結合 **20 軌邏輯分析儀脈衝視圖**、**即時網路抓包監控** 與 **EtherCAT PDO 數位示波器數值階梯波形**。

---

## 環境需求與快速開始

### 1. 系統需求
- **Python 3**（僅使用標準函式庫，無須安裝額外第三方套件）
- **Wireshark**（需包含 `tshark` 與 `capinfos` 命令列工具）
  - **跨平台路徑自動偵測**：依序搜尋系統 `PATH`、環境變數（`WIRESHARK_PATH`、`WIRESHARK_HOME`、`WIRESHARK_DIR`），以及各作業系統常見安裝位置：
    - **Windows**：自動查詢系統機碼（`App Paths`、`SOFTWARE\Wireshark`、`SOFTWARE\WOW6432Node\Wireshark`）、`ProgramFiles` 與常見磁碟安裝路徑。
    - **macOS / Linux**：`/Applications/Wireshark.app/Contents/MacOS`、`/usr/local/bin`、`/opt/homebrew/bin`。

### 2. 啟動方式
1. 將要分析的 `.pcap` 或 `.pcapng` 封包檔放入專案根目錄（或使用內建即時抓包功能直接錄製）。
2. 在專案目錄執行：
   ```bash
   python serve.py
   ```
   （macOS / Linux 可執行 `./serve.py` 或 `python3 serve.py`；啟動前在 macOS / Linux 會自動清理佔用 `8765` 埠的舊行程。）
3. 開啟瀏覽器連線至：
   ```text
   http://127.0.0.1:8765
   ```

---

## 核心功能

### 1. 即時抓包監控（Live Capture）
- 頁面頂部即時監控列可透過 `tshark -D` 自動列出可用網路介面卡。
- 點擊 **「開始即時監控」** 後，將封包以 `pcap` 格式即時寫入 `live_capture.pcap`。
- 錄製期間前端每 **1.5 秒**自動重新整理檔案清單並觸發掃描，即時更新邏輯分析儀與數位示波器波形。
- 點擊 **「停止監控」** 或結束 `serve.py` 時，會透過 `atexit` 與 `finally` 自動終止背景 `tshark` 抓包行程。

### 2. 邏輯分析儀（20 軌脈衝視圖）
- 最多支援 **20 軌（`CH1`–`CH20`）**，每軌可輸入任意 Wireshark Display Filter，使用多執行緒（`ThreadPoolExecutor(max_workers=8)`）平行掃描，符合條件的封包會在對應時間點繪製發光脈衝。
- **過濾條件記憶**：依封包檔名自動儲存與載入各軌過濾規則至瀏覽器 `localStorage`。
- **隱藏未監控軌道**：
  - 預設隱藏沒有設定過濾條件的空白頻道（若全為空則保留 `CH1`），畫布高度依顯示軌道數自動調整。
  - 提供 **「+ 新增頻道」** 逐一顯示下一個空白頻道，以及 **「顯示全部 (20) / 隱藏空白軌」** 切換檢視；按下「掃描」時會自動收合仍為空白的頻道。
- **固定尺寸下方狀態列**：底部讀數區（`#readout`）固定為 `408px` 高度（內含捲軸），不受上方數位示波器或邏輯分析儀高度變化影響，可一次完整顯示全部 20 軌於游標時間點的命中封包編號、協定與摘要資訊。

### 3. 數位示波器（EtherCAT PDO / USB CDC 數值波形）
- 當任一頻道使用 `pdo:`、`cdc:` 或 `usb:`（數值型態）語法時，系統會在畫面上方自動展開 **數位波形示波器**，依實際工程數值（Y 軸）與相對時間（X 軸）繪製階梯波形（Step Waveform）。
- 每軌左側面板顯示頻道編號、Byte/Bit 位置標籤、資料型態、目前最新數值及整體 `Min / Max`；畫布上會於數值變化的轉折點畫上圓點並自動避讓標註數值。
- **波形與切幀規則產生器**：點擊 **「📈 波形與切幀規則產生器 (PDO / USB CDC)」** 可切換 `pdo:`、`cdc:`（含串流重組）、`usb:`（逐包解析）來源，圖形化設定基礎過濾條件、USB CDC 切幀規則（自動記憶於瀏覽器）、Byte/Bit 位置、資料格式與端序（Little/Big-Endian），即時預覽語法並點擊 **「填入空白頻道並掃描」**（或在產生器輸入欄按 `Enter`）直接套用並掃描。
- **同步縮放與平移**：
  - 提供同步時間刻度軸（`#pdo-axis`）與跨頻道垂直游標線。
  - 支援滾輪縮放時間（最小視窗 `20 µs`）、左鍵拖曳平移、雙擊畫布／時間軸或點擊 **「全程」** 重設回全程。
  - 即時抓包重新掃描同一檔案時，若原本處於全程檢視會自動延伸至最新時長；若正在局部放大檢視則保留目前時間視窗。

### 4. USB CDC（Virtual COM）串流重組（`cdc:` / `usb:`）
- USB CDC 在底層 Bulk IN 傳輸時常因 Short Packet（例如第 1 Byte `0xFF` 先送、剩餘資料下一包才送）或 Coalescing（多包黏在一起）導致單一 Wireshark Filter 漏包或錯位。
- 使用 **`cdc:`** 前綴可依使用者自訂的切幀規則在後端重組完整封包（並於脈衝與數值變化摘要標註 `[重組N包]`），支援輸出為：
  - **`frame` 模式**：於邏輯分析儀打出每個重組完成封包的脈衝與摘要。
  - **數值波形模式**：對重組後的完整封包解析指定 Byte/Bit（支援 `le` / `be`），繪製於數位示波器並支援多組時間測量。

### 5. 多組時間測量工具（邏輯分析儀與數位示波器皆支援）
- **建立多組測量區塊**：點擊工具列的 **「📏 測量」** 切換測量模式後拖曳，或於一般模式下按住 **`Shift + 拖曳`**，即可建立多組不同顏色的時間測量區間（`M1`、`M2`、`M3`…）。
- **僅於滑鼠懸停時顯示統計**：畫布上平常只顯示半透明區間色塊與左上角 `M{id} ×` 標籤，維持畫面簡潔；當滑鼠移入任一測量區塊時，才會在游標旁浮動顯示該區間的統計資訊：
  - **邏輯分析儀**：顯示 `T1`、`T2`、`ΔT`、`1/ΔT`、總計事件數，以及區間內各活躍軌道的觸發次數、平均週期與頻率。
  - **數位示波器**：顯示 `T1`、`T2`、`ΔT`、`1/ΔT`，以及懸停該頻道的起始值、結束值、`ΔVal`、最小值、最大值、時間加權平均值與變化次數（若為 `bit` / `bool` 型態，另顯示高電位時間與佔空比 `%`）。
- **刪除與清除**：
  - 單筆刪除：點擊測量區塊左上角的 **`×`** 按鈕，或在測量區塊上按**滑鼠右鍵**。
  - 全部清除：點擊工具列的 **「清除測量」** 按鈕（切換不同檔案時亦會自動清除）。

### 6. 高精度時間軸與讀數顯示（達 `0.1 ms` 精度）
- 邏輯分析儀與數位示波器的時間軸刻度、游標時間與測量區間讀數皆具至少 **`0.1 ms`** 解析度：
  - `< 1 ms`：顯示微秒 `µs`（精確至 `1 µs`）
  - `1 ms` – `< 1 s`：顯示毫秒 `ms`（`< 10 ms` 保留 2 位小數、`>= 10 ms` 保留 1 位小數，精確至 `0.01 ms` / `0.1 ms`）
  - `>= 1 s`：顯示秒 `s`（固定保留 4 位小數 `0.0001 s`，即 `0.1 ms` 精度）

---

## 數值與切幀過濾語法參考

### 一、EtherCAT PDO（`pdo:`）

只要頻道過濾文字以 `pdo:` 開頭（不分大小寫），後端即會改以 EtherCAT PDO 數值解析引擎讀取 `ecat.data` 並繪製數位波形。

#### 語法格式（以 `|` 分隔）

| 用途 | 語法格式 | 範例 |
| --- | --- | --- |
| 一般數值 | `pdo: <基礎過濾> \| <byte_offset> \| <type> [\| <datagram_index>]` | `pdo: ecat.ado == 0x1000 \| 4 \| int16 \| 0` |
| 單一 Bit | `pdo: <基礎過濾> \| <byte_offset>.<bit_index> \| bit [\| <datagram_index>]` | `pdo: ecat \| 0.3 \| bit \| 0` |
| 原始 Hex | `pdo: <基礎過濾> \| <byte_offset>:<length> \| hex [\| <datagram_index>]` | `pdo: ecat \| 2:4 \| hex \| 0` |

#### 欄位與資料型態說明
- **`基礎過濾`**：標準 Wireshark Display Filter，留空時預設為 `ecat`。
- **`byte_offset`**：Payload 內的 Byte 起始偏移（從 `0` 起算，支援十進位與 `0x` 十六進位）。
- **`bit_index`**：`0`–`7` 之間的 Bit 索引；使用 `.` 指定時會自動以 `bit` 模式解析。
- **`type`**：預設為 `uint16`，數值解析一律採用 **Little-Endian**：
  - 布林／位元：`bit`、`bool`
  - 整數：`uint8`、`int8`、`uint16`、`int16`、`uint32`、`int32`、`uint64`、`int64`
  - 浮點數：`float`（`float32`）、`double`（`float64`）
  - 原始位元組：`hex`、`bytes`（以 `xx:xx` 格式化文字顯示，Y 軸以 Little-Endian 無號整數繪製）
- **`datagram_index`**：選填，單一 EtherCAT Frame 內含多個 Datagram 時指定取第幾個（從 `0` 起算，預設 `0`）。

---

### 二、USB CDC / Virtual COM（`cdc:` 與 `usb:`）

#### 語法格式（以 `|` 分隔，條件內可正常使用 `||`）

| 用途 | 語法格式 | 範例 |
| --- | --- | --- |
| CDC 重組脈衝 | `cdc: <基礎過濾> \| <切幀規則> \| frame` | `cdc: usb.src == "3.19.1" && usb.capdata \| head=ff,tail=ee,len=27 \| frame` |
| CDC 重組數值波形 | `cdc: <基礎過濾> \| <切幀規則> \| <byte_offset> \| <type> [\| <le/be>]` | `cdc: usb.src == "3.19.1" && usb.capdata \| head=ff,tail=ee,len=27 \| 5 \| uint16 \| le` |
| CDC 重組 Bit / Hex | `cdc: <基礎過濾> \| <切幀規則> \| <offset.bit 或 offset:len> \| <bit/hex>` | `cdc: usb.capdata \| head=ff,tail=ee,len=27 \| 1.0 \| bit` |
| USB 逐包解析（無重組） | `usb: <基礎過濾> \| <byte_offset 或 frame> [\| <type>] [\| <le/be>]` | `usb: usb.src == "3.19.1" && usb.capdata \| 5 \| int16 \| be` |

#### `切幀規則` 支援參數（以 `,` 分隔 `key=value`，留空或 `none` 表示不重組）

| 參數 | 說明 | 範例 |
| --- | --- | --- |
| `head` | 幀頭 Hex Bytes（可用空格、`:`、`-` 或 `0x`，亦支援純幀頭分隔多包） | `head=ff`、`head=aa55` |
| `tail` | 幀尾 Hex Bytes（可單獨作為結束符或搭配 `head` / `len` 驗證） | `tail=ee`、`tail=0d0a` |
| `len` | 固定總幀長（Bytes）；搭配 `head`/`tail` 時若對不齊會自動重同步 | `len=27` |
| `len_off` | 動態長度欄位在封包內的 Byte 偏移（從 `0` 起算，不可與 `len` 同時使用） | `len_off=1` |
| `len_size` | 動態長度欄位寬度（`1` 或 `2` Bytes，預設 `1`） | `len_size=2` |
| `len_bias` | 總幀長偏差值（`總幀長 = 長度欄位值 + len_bias`，預設 `0`） | `len_bias=4` |
| `len_endian` | 動態長度欄位的位元組序（`le` / `be`，預設 `le`） | `len_endian=be` |
| `gap` | 超時分幀間隔（`ms`）；兩包間隔超過此時間即切出當前緩衝或捨棄殘留半包 | `gap=5` |
| `match` | 對重組後的完整幀做內容比對（`offset:hex`，多組以 `;` 分隔） | `match=1:01`、`match=1:01;2:00` |
| `ts` | 該重組封包的時間戳記取基準：`end`（收齊最後一包，預設）或 `start`（第一包到達） | `ts=start` |
| `field` | `tshark` 擷取的 Hex 欄位名稱（預設 `usb.capdata`） | `field=usb.capdata` |

#### 支援端序與型態
- 除完整支援上述 `bit`、`bool`、`uint8~64`、`int8~64`、`float`、`double`、`hex` 與脈衝專用 **`frame`** 外，`cdc:` 與 `usb:` 可透過第 5 欄（`le` / `be`）或型態後綴（如 `uint16_be`、`float_be`）切換 Little-Endian / Big-Endian。

---

## 快速操作對照表

| 操作 | 功能 |
| --- | --- |
| 滾輪向上 / 向下 | 以滑鼠所在時間為中心放大 / 縮小時間軸（邏輯分析儀與數位示波器皆適用） |
| 左鍵拖曳 | 左右平移時間視窗 |
| 雙擊畫布或時間軸 / 點「全程」 | 回到整份封包的全程時間範圍 |
| 開啟「📏 測量」後拖曳，或 **`Shift + 左鍵拖曳`** | 建立一組新的時間測量區間 |
| 將滑鼠移至測量區塊上 | 顯示該測量區間的統計浮動視窗 |
| 點測量區塊左上角 `×` 或在區塊上**按右鍵** | 刪除該筆測量區間 |
| 在頻道過濾欄或 PDO 產生器輸入欄按 **`Enter`** | 立即觸發掃描 |

---

## HTTP API 端點與檔案結構

### 後端 API（[serve.py](serve.py)）
- `GET /`：提供網頁介面（讀取 `static/index.html` 並注入即時抓包面板與數位示波器前端）
- `GET /api/files`：列出專案根目錄內所有 `.pcap` / `.pcapng` 檔案（依修改時間由新到舊排序）
- `GET /api/interfaces`：回傳 `tshark -D` 偵測到的系統網卡清單
- `GET /api/capture/status`：查詢目前即時抓包狀態（`running`、`interface`、`file`）
- `GET /api/meta?file=<filename>`：透過 `capinfos` 回傳封包數與擷取總時間
- `POST /api/capture/start`：指定網卡開始即時抓包並寫入 `live_capture.pcap`
- `POST /api/capture/stop`：停止即時抓包
- `POST /api/scan`：傳入 `file` 與 `filters` 陣列（最多 20 軌），回傳各軌事件與 PDO 數值波形資料

### 檔案結構
```text
Wireshark_Package_Tool/
├── serve.py            # 本地 HTTP 伺服器、tshark/capinfos 封裝、PDO / USB CDC 解析引擎與數位示波器前端
├── static/
│   └── index.html      # 20 軌邏輯分析儀介面、時間軸控制與多組時間測量工具
├── *.pcap / *.pcapng   # 欲分析的封包檔或即時抓包輸出 (live_capture.pcap)
└── README.md           # 專案說明文件
```
