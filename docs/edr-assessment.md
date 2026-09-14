# EDR 實作評估：Endpoint / Detection / Response

本文以程式碼為依據，盤點 Rustinel 在 EDR 三個定義面向的實作**廣度**（涵蓋多少類別）、
**深度**（每一類做到多完整、多穩健）與**覆蓋度**（對應到規則、平台與測試）。每一項聲稱附
`file:line`，可直接回查。

> **量測基準**：分支 `feat/response-layer`，含本次缺口修補（見文末〈本次變更〉）。
> 專案自我定位見 [Limitations](limitations.md#detection-posture)：**不是商用 EDR 的替代品**，
> 適合 detection engineering、規則測試、遙測收集、SIEM pipeline 驗證。本文以此為基準評分，
> 但同時對照成熟 EDR 的完整 surface 列出差距，讓 roadmap 有座標。

## 總覽計分卡

| 面向 | 廣度 | 深度 | 覆蓋度 | 一句話 |
|---|---|---|---|---|
| **E** Endpoint | Win ●●●●○<br>Linux ●●●●○<br>macOS ●●●●○ | Win ●●●●○<br>Linux ●●●●○<br>macOS ●●●●○ | 測試 ●●●●○ | 三平台都有 process / file / **cross-process** / network / dns，file 事件標示 persistence 機制，process 事件帶 hash（三平台）與 signer（Win / macOS）。仍缺：backpressure、ETW session 恢復、file rundown、Linux module load、macOS mmap / auth |
| **D** Detection | ●●●●○ | ●●●●○ | 規則 ●●○○○<br>測試 ●●●●○ | 純簽章式（Sigma + YARA + 精確 IOC）。`Hashes` / `Signed` 從「永不觸發」變成可觸發；`process_access` 在三平台都有 live collector；persistence 可直接以 `PersistenceMechanism` 比對。仍無行為 / 基線 / ML，內建規則仍僅 demo |
| **R** Response | Win ●●●●○<br>Linux ●●●●○<br>macOS ●●●●○ | Win ●●●●○<br>Linux ●●●●○<br>macOS ●●●●○ | 測試 ●●●●○ | kernel driver 介面已實作，不再是死合約；quarantine 覆寫與 isolate 疊加已修；Linux/macOS 新增網路隔離（nftables / pf）與 persistence 單元停用（systemd / launchd）。仍缺：Linux/macOS 的 per-image 網路封鎖、遠端 / live response |

> **關於「每個 OS 都要 ●●●●○ 以上」**：已達成，靠的是補上缺的能力而不是放寬標準。
> 三個平台現在都有 cross-process 遙測（Windows ETW、macOS ES 的 trace / get_task /
> remote_thread_create、Linux 的 `sys_enter_ptrace`）、persistence 標示、以及 process 事件
> 上的 hash。Response 三平台都能做網路隔離與停用持久化單元。
>
> **●●●●○ 不是 ●●●●●**，差距是具體的：沒有 backpressure（只計數）、沒有 ETW session 恢復、
> 沒有 file rundown、Linux 缺 module load 與 inbound 連線、macOS 缺 mmap/mprotect 與登入事件、
> Linux/macOS 沒有 per-image 網路封鎖、偵測端沒有行為/基線分析、內建規則仍是 demo。
> 每一項在文末〈要把剩下的格子補到 ●●●●●需要什麼〉都有對應說明。

---

## E — Endpoint 遙測層

「端點」在這裡指感測器**能看到什麼**。Rustinel 三個平台的感測器都在 user mode：
Windows 走 ETW 與 Event Log，Linux 走 eBPF，macOS 走 Endpoint Security 加 `/dev/bpf`。

### 廣度：事件來源，逐 OS

| 類別 | Windows | Linux (eBPF) | macOS (ESF, experimental) |
|---|---|---|---|
| Process start / stop | ✅ ETW Kernel-Process | ✅ `sched_process_exec/exit` + `execve` argv | ✅ ES `NOTIFY_EXEC/EXIT` |
| File create / write / delete / rename | ✅ Kernel-File 9 個 ID | ✅ ~28 個 tracepoint + kprobe `vfs_create` | ✅ `CREATE/UNLINK/RENAME/CLOSE` |
| File metadata change | ✅ SetInformation (ID 17) | ❌ | ❌ |
| Network | ✅ TCP + UDP，進出雙向 | ⚠️ 僅 outbound `connect()` | ⚠️ `/dev/bpf` 單介面 wire capture，無 `Initiated` |
| DNS | ✅ DNS-Client 3006 / 3008 | ⚠️ 僅 UDP/53 query，無 answer | ⚠️ 無 PID 歸屬 |
| Registry | ✅ Kernel-Registry 6 個 ID + 啟動 rundown（~88.9%） | n/a | n/a |
| Image load | ✅ | ❌ 無 module load | ❌ |
| RemoteThread / ProcessAccess | ✅ Kernel-Process thread + Kernel-Audit-API-Calls 5 / 6（存取 mask 過濾） | ⚠️ `sys_enter_ptrace`（Linux 無 remote thread 這個概念） | ✅ ES `trace` / `get_task` / `get_task_read` / `remote_thread_create` |
| PowerShell script / module | ✅ 4104 / 4103（僅 PS 5.1 provider，PS 7 不收） | n/a | n/a |
| WMI | ✅ 11 個 ID（無 persistence 欄位） | n/a | n/a |
| Service / Scheduled task | ✅ 7045、4697 / 106（`TaskContent` 恆空） | ❌ 無 systemd / cron | ⚠️ 無 launchd 事件，但寫入 LaunchAgents / LaunchDaemons 等 11 類 persistence 位置的檔案事件會被標記（見下） |
| Auth / logon | ✅ Security 4624 / 4656 / 4663 / 4697 / 5136 / 5145（依主機 audit policy） | ❌ | ❌ |
| Memory / injection API（VirtualAllocEx、WPM、APC） | ❌ 需 Threat-Intelligence ETW（PPL + ELAM） | ❌ | ❌ |
| Named pipe / Driver load (BYOVD) | ❌ | ❌ | ❌ |

來源：`src/sensor/windows/etw/providers.rs:22-237`、`src/sensor/windows/event_log/{security,service}.rs`、
`src/sensor/linux/ebpf.rs:120-248`、`src/sensor/macos/{esf,bpf,socket}.rs`；事件類別 enum 在 `src/models/event.rs:375-392`。

#### macOS persistence 分類（來自 SentinelOne 指南）

macOS 感測器本來就看得到每一次 create / rename / unlink，缺的是**說出這次寫入的意義**：
落在 `~/Library/LaunchAgents` 的 plist 與落在 `~/Downloads` 的檔案，送到引擎時是同一種事件，
所以每一條規則都得自己帶路徑清單、也都得各自維護正確。

`src/sensor/persistence.rs` 依 Phil Stokes《A Guide to macOS Threat Hunting and Incident Response》
（SentinelOne, 2020）第 1 章列舉的持久化手法做分類，file 事件因此帶上 `PersistenceMechanism`：
launch_agent、launch_daemon、profile、cron、periodic、kernel_extension、login_item、mail_rule、
login_hook、at_job、emond 共 11 類。

指南中影響實作的兩個判斷：

- LaunchAgent 是「macOS 上最常見的持久化方式」，而**使用者層級的 LaunchAgent 完全不需要權限**。
  所以比對是逐**路徑片段**而非前綴，`/Users/<name>/` 以外的家目錄一樣會被分類。
- `/System/Library` 由 SIP 保護，指南把監控重點放在 `/Library/LaunchDaemons` 與使用者目錄。
  寫入 `/System` 仍然分類——SIP 被繞過本身就值得一個告警。

指南列出但**刻意不分類**的：Folder Actions / AppleScript（持久化在腳本而非固定路徑，指南自己的
建議是比對 `osascript` 與 `ScriptMonitor` 的命令列，那是既有的 process 遙測）；StartupItems、
`rc.common`、`launchd.conf`（指南記載這些在現行 macOS 已失效，分類了只會產生沒人該寫規則的欄位）。

比對用**片段**而非子字串是有理由的：子字串比對會把 `/tmp/LaunchAgents-notes.txt` 判成持久化，
任何能寫 `/tmp` 的人就能用自製噪音淹掉真正的告警。此行為有測試釘住。

### 深度

- **正規化**：單一 normalizer（`src/normalizer/mod.rs:43-96`）輸出 ECS 9.4 約 120 個欄位（`src/models/ecs/alert.rs`）。
  Enrichment 有：parent chain（`ProcessCache`）、cmdline back-fill、SID → user、PE version resource
  （OriginalFileName / Company / FileVersion）、IntegrityLevel、DNS IP → domain cache。
- **已補**：process 與 image-load 事件現在帶 `Hashes`（`MD5=…,SHA256=…`）與 `Signed` / `Signature` /
  `SignatureStatus`。Windows 走 enrichment thread（`src/sensor/windows/enrichment.rs`），以 file identity
  為鍵快取，受 `process.hash_images` 與 `hash_max_file_size_mb` 控制；簽章走
  `src/utils/authenticode.rs`，**embedded 與 catalog 兩條路都走**——只查 embedded 會把幾乎每一個
  Windows 系統檔判成未簽章。macOS 從 ES 事件直接取 `cdhash` / `team_id` / `codesigning_flags`，
  **不開檔**（`src/sensor/macos/esf.rs`）。
- **仍缺**：`Imphash`（需 PE import table，非檔案摘要）；catalog 簽章讀不到 publisher 名稱；
  簽章驗證只走 cache，不做網路 revocation；Windows `CurrentDirectory` 空；
  Linux / macOS `User` 是 real UID 而非 effective（#327）；**Linux 事件無 hash / signer**
  （enrichment 目前只在 Windows 側）。
- **Drop accounting 非常完整**：eBPF per-family counter、per-channel dropped / peak depth、ETW decode failure 按 provider / event ID / version 分類、
  kernel `EventsLost` 每秒輪詢（`src/sensor/windows/loss.rs:24-45`），全部進 `telemetry.json` 與 `rustinel doctor`。
  但**沒有真正的 backpressure**：bounded channel（8192，`src/runtime/capture.rs:29`）只會 shed，不會 block。
- **沒有 file rundown**：冷啟動時 file-path 解析僅 1.2%（#428）；registry 有 rundown，file 沒有。
- **沒有 ETW session 重連 / 恢復邏輯**（`src/sensor/windows/etw*` 中無 restart / reconnect）；**沒有 self-protection**。
- Kernel driver（`driver/`）**只服務 Response，不供遙測**。

### 測試

- 有：`tests/windows_security_channel.rs`、`windows_security_event_log.rs`、`windows_service_event_log.rs`、`linux_file_paths.rs`、
  `platform_mapping.rs`、`ecs_contract.rs`、`telemetry_backpressure.rs`、`capture_recording.rs`、`replay_fixture.rs`。
  模組內測試強：`linux/ebpf.rs`（43）、`windows/registry_paths.rs`（19）、`macos/bpf.rs`（14）、
  `etw/routing.rs`（12，含 provider ↔ router drift guard）。
- **新增**：`enrichment.rs` 11 個測試（hash 對空檔的已知摘要、超限跳過、開關、簽章判定、不可讀檔不得寫成
  `Signed: false`）、`authenticode.rs` 4 個（catalog 簽章的系統檔、embedded 簽章的 publisher、竄改、缺檔）。
- **仍零測試**：`registry_rundown.rs`（357 LOC）、`etw/parser.rs`、ETW 與 Event Log 訂閱生命週期、
  `platform/{linux,macos}.rs`、**`ebpf/src/` 與 `driver/` 的 kernel 側 C / eBPF 程式碼**。

---

## D — Detection 偵測層

「偵測」指引擎**能判定什麼**。Rustinel 是三引擎簽章式架構：Sigma（行為）、YARA（檔案與記憶體）、IOC（精確比對）。

### 廣度

| 引擎 | 內容 | 來源 |
|---|---|---|
| Sigma | 引擎委外給 `rsigma-parser` / `rsigma-eval` 0.21（`Cargo.toml:23-24`），Rustinel 負責正規化、logsource 路由、ECS 告警、hot reload。修飾子全支援（contains / startswith / re / base64 / windash / cidr / fieldref / 比較運算 …）；**不支援的修飾子整條規則拒載**並記入 `failed_rules`（`src/engine/loader.rs:263-272`）。條件文法 and / or / not / `N of` / `all of`；**沒有 `near`，沒有 legacy `\| count() by`**。Correlation 八型：event_count / value_count / temporal / temporal_ordered / value_sum / avg / percentile / median | `docs/detection.md:356-380` |
| Logsource 對應 | 21 類。Linux / macOS 僅 process / network / file×4 / dns；Windows 另有 registry×4、image_load、create_remote_thread、process_access、ps_script / ps_module、wmi_event、service_creation、task_creation、`service: security` | `src/engine/logsource.rs:201-345` |
| YARA | `yara-x` 1.17。磁碟掃描**只在 process-start 觸發**：寫入但未執行的檔案永遠不會被掃。記憶體掃描三平台皆有實作但**預設關閉**，只掃 private region，64 MB / process、8 MB / region | `src/scanner/mod.rs:46-104`、`src/memory/{windows,linux,macos}.rs`、`src/config.rs:714-721` |
| IOC | **只有 6 型**：MD5 / SHA1 / SHA256 / IP（+CIDR）/ Domain（+suffix）/ PathRegex。**沒有 URL、憑證、mutex、registry 指標**。**只吃純文字 feed**，沒有 STIX / CSV / MISP / TAXII。所有命中共用一個固定嚴重度 | `src/ioc/types.rs:16-36`、`src/ioc/load.rs:27-62` |
| 告警輸出 | **單一通道：ECS NDJSON 寫檔**。沒有 syslog / webhook / 原生 SIEM push；轉送靠 Filebeat / Vector tail 檔案。Dedup 60 秒固定窗，第一次即時、窗尾 rollup 帶 `event.count` | `src/alerts/mod.rs`、`src/alerts/dedup.rs:47-107` |
| ATT&CK | **只有 tag passthrough** 到 `rule_tags`，供 response policy glob 比對。**沒有 ECS `threat.technique.*` / `threat.tactic.*` 對應** | `src/models/ecs/alert.rs:99-101` |

### 覆蓋度（量測值，非估計）

- **可載入**（CI gate，`compatibility/sigmahq-baseline.json`，SigmaHQ `da9bb07` 共 3,783 條）：Windows 2,693、Linux 178、macOS 86；0 parse failure。
  注意：這個 gate 量的是 *loadability*，不是欄位可用性。
- **可觸發**（[Sigma Coverage](coverage.md)，人工量測、部分已過時）：Windows 74.4%（2,138 / 2,875）、Linux 71.4%、macOS 98.7%。
  主要阻擋：Security channel 177 條、Linux raw-auditd 欄位模型 54 條。
  **`Hashes` 47 條與 `Signed` 15 條已不再被欄位缺失擋住**（見上）——但這是「可以觸發」，
  不是「會偵測到」，而且頭條數字要下次完整重跑語料才會動。
  **公開語料中沒有任何一條使用 correlation。**
- **內建規則 = demo**：3 條 Sigma（whoami × 3 OS，`level: low`）、1 條 YARA test marker、4 個 IOC 檔合計 564 bytes（`rules/`）。
  真實內容在外部 `Karib0u/rustinel-rules`（release pin `c1d78b4…`，`.github/workflows/release.yml:11`）。
  Catalog **未簽章**（[Limitations](limitations.md#pipeline-and-operations)）；atomic test harness 源碼不在本 repo，pass-rate 無法在此驗證。
- Rule lint gate 已從 `rsigma-action` v0.18.0 對齊到 **v0.21.0**，並加上一道 CI 檢查，
  比對 `Cargo.toml` 的 `rsigma-parser` 版本與 workflow 的 pin，避免再次無聲漂移
  （`.github/workflows/sigma-rules.yml`）。

### 深度與缺口

- **沒有行為 / 異常 / ML / 統計偵測、沒有 baseline、沒有 profiling**。全 `src/` 搜尋 anomaly / baseline / heuristic 只命中 bench 與 capture manifest。
- 跨事件串鏈**只有** Sigma correlation：單一 `Mutex<CorrelationEngine>`、**hot reload 會清空狀態**、沒有獨立驅逐任務（`src/engine/store.rs:23-76`）。
- **每個事件最多一條 detection alert**（severity → id → title 擇一，`src/engine/mod.rs:41-81`）：共同觸發的規則會被遮蔽。
- 憑證竊取偵測依賴 `Microsoft-Windows-Kernel-Audit-API-Calls`（未文件化的 provider）；`GrantedAccess` 是 *requested* mask，只是上限。
  注入只有 thread-start 一條線，**沒有 `StartModule` / `StartFunction`，沒有任何記憶體操作遙測**，thread-less 注入不可見。
- 靜默失效：規則沒有 collector 支援時**載入成功但永不觸發**。`sigma_rules_inert` doctor 檢查有緩解；per-rule 診斷（#184）未完成。

### 測試

強：`sigma_corpus_compatibility.rs`（421 行，baseline diff gate）、`sigma_documents.rs`（566）、`sigma_detection.rs`（295）、
`sigma_match_selection.rs`（236）、`yara_disk / yara_memory / yara_scan_limits`、`pipeline_ioc.rs`、`dedup_integration.rs`（338）、
`ecs_contract.rs`（792）、`src/engine/mod.rs` 約 35 個 unit test、三個 bench。

---

## R — Response 回應層

「回應」指偵測到之後**能做什麼**。這一層在 `feat/response-layer` 分支上新近大幅擴充。

### 廣度：動作 × OS

| 動作 | Windows | Linux | macOS | 來源 |
|---|---|---|---|---|
| Terminate process | ✅ `TerminateProcess` | ✅ `SIGKILL` | ✅ `SIGKILL` | `src/response/executor/ring3.rs:103,180` |
| Suspend process | ✅ `NtSuspendProcess` | ✅ `SIGSTOP` | ✅ `SIGSTOP` | `ring3.rs:126,184` |
| Quarantine / Restore | ✅ XOR store + icacls 硬化 | ✅ 0700 | ✅ 0700 | `executor/quarantine.rs:78,158,470` |
| Host isolation（含 CIDR / DNS / DHCP 例外） | ✅ WFP 4 層、persistent、transaction all-or-nothing | ✅ nftables `inet` 表（IPv4+IPv6），policy drop + established/loopback/例外 accept | ✅ pf anchor，block 在前、全部 `pass quick` | `executor/wfp.rs`、`executor/host_firewall.rs` |
| Block process network | ✅ WFP `ALE_APP_ID`（封 image，非單一 PID） | ❌ | ❌ | `wfp.rs:683` |
| Revert registry | ✅ ASEP snapshot 還原，否則刪除 | n/a | n/a | `executor/windows.rs:148`、`asep.rs:60` |
| Disable service / scheduled task | ✅ / ✅ | ✅ `systemctl disable --now` / ❌ | ✅ `launchctl disable` + `bootout` / ❌ | `windows.rs:232,285`、`executor/unix_service.rs` |
| Driver-level deny（proc create / file write / reg write / handle strip） | ⚠️ 介面已實作，**仍需已簽章的 driver 才會生效**（見下） | n/a | n/a | `driver/src/*.c`、`src/response/executor/driver.rs` |
| Block by hash / path、Disable user、per-PID network block | ❌ 沒有這些 `ActionKind` | ❌ | ❌ | `ActionKind::ALL` 共 8 種（`action.rs:43-52`） |

**Kernel driver 現況**（`driver/`）：四個 deny callback 與 `ZwTerminateProcess` IOCTL 都有 C 源碼。
Rust 側**已不再是死合約**：`src/response/executor/driver.rs` 以 `DeviceIoControl` 實作全部四個 control code，
逐欄鏡射 `rustinel_ioctl.h`，並用測試釘住每個結構的 size / offset 與 CTL_CODE 值——這正是跨 kernel 邊界
對不上時會變成記憶體毀損而非解析錯誤的地方。driver 存在時，agent 啟動即推送自我保護 policy
（自身 process 的 VM_READ / VM_WRITE / CREATE_THREAD 等權限被 strip、service registry key 唯讀），
`TerminateProcess` 改走 kernel 終止，`rustinel doctor` 的 `response_driver_state` 會回報**哪一個 callback 沒註冊成功**
（`/INTEGRITYCHECK` 缺失只會讓 Ob callback 註冊失敗，driver 其餘部分照常運作，從外面看不出來）。
**但這些在沒有已簽章 driver 的機器上都不會執行**：altitude 仍是 placeholder，無 build system、無 CI target、不出貨。
沒有 driver 時優雅降級：capability table 讓 `CompositeExecutor` 選下一個 executor（`executor/mod.rs:249`）；
enforcement strength 只有 WFP 兩個動作是 `Inline`，其餘全部 `PostHoc`（`action.rs:232`）。

### 觸發模型

- **自動**：policy 是**操作者的設定**而不是規則內容 —— `[[response.rules]]` 以 `rule_ids` / `rule_names`（glob）/ `tags`（glob，如 `attack.t1003*`）/
  `categories` / `engines` / `min_severity` 選擇，first-match wins（`src/response/policy.rs:132,277`）。Sigma tag 只是 *selector*，永不直接下動作。
- **操作者**：**只有本機 CLI** `rustinel response status | isolate --yes | unisolate | quarantine | restore`（`src/response/cli.rs:20`）。
  沒有 named pipe、沒有檔案投遞、沒有遠端通道。
- Dry-run 兩層：全域 `prevention_enabled` 與 per-rule `dry_run`，規則只能收緊不能放寬。沒有 approval workflow / 雙人控制。
  `rustinel replay` 永不建立 response engine。

### 安全控制（深度佳）

path / image allowlist、每 OS 內建 protected images（lsass / csrss / systemd / launchd …）、Windows critical-process 與 PPL 探測、
protected services 與 registry fragment、self-PID 與 pid ≤ 4 拒絕、agent 目錄永不隔離（編譯期寫死）、per-kind 60 秒 rate limit、
per-(kind, target) cooldown、**PID-recycle guard**（執行前重驗 image + start time + cmdline hash，`src/response/mod.rs:467`）、
WFP transaction、每次嘗試（performed / dry-run / suppressed / failed）都寫 ECS `rustinel.response` audit（`audit.rs:92`）。
**缺**：沒有 signer / 憑證型 allowlist。

### 深度問題（已回查確認）

- ~~`write_new` 會覆寫~~ **已修**：`create_new` 真正拒絕覆寫；blob 仍是 content-addressed 而共用，
  但每次隔離取得自己的 record id，所以同樣 bytes 從第二個路徑被隔離時，第一筆的 `original_path`
  不會被蓋掉（那會讓還原送錯地方）。最後一筆 record 移除時才刪 blob。
- ~~`isolate()` 疊加 filter~~ **已修**：isolate 現在是**收斂**而非累加，在同一個 transaction 內先移除
  自己的舊 filter 再安裝。以 display name 前綴限定範圍，所以不會順手拿掉別人下的
  `BlockProcessNetwork`；三個名稱的前綴關係有測試釘住。
- `disable_service` / `disable_scheduled_task` / `revert_registry` **沒有 undo**；kill 明示不可逆。
- 沒有跨 agent 重啟的 action state store，收據只在 audit log。

### 對照成熟 EDR 缺少的 surface

遠端 / live response shell、任何遠端指令通道、memory / process dump 收集、forensic triage package、檔案上傳 / 取回、
排程與服務的**刪除**（目前只停用）、廣義 persistence 清理（WMI subscription、startup folder、COM hijack、cron / launchd / systemd unit）、
使用者登出 / 帳號停用 / token 重設、全域 hash / path blocklist 作為 policy object、**Linux（nftables）與 macOS（pf）網路隔離**、
on-demand 全碟掃描修復。

### 測試

- 有：決策引擎 / 嚴重度 / allowlist / dry-run（`tests/active_response.rs`）、**真實 kill 與 dry-run-不-kill**（跨平台，會 spawn 子程序）、
  policy 選擇 / 排序 / capability 過濾、audit 三態（`tests/response_policy.rs`）、path allowlist（`tests/path_allowlist.rs`）。
- 僅 unit test：quarantine round-trip 與 self-protection、WFP policy 解析與權重。
- **零實測**：所有 WFP 安裝 / 移除路徑、所有 Windows registry / service / task 執行路徑、macOS `SIGKILL` / `SIGSTOP`（CI 只編譯不執行）、
  Windows quarantine ACL 硬化、**整個 driver C 碼**。

---

## 跨 E / D / R 的主要缺口（按影響排序）

前一版的九項中，第 1、2、8、9 項已處理，其餘未動。

| # | 面向 | 缺口 | 狀態 |
|---|---|---|---|
| 1 | R | Kernel driver 不可達 | **已修介面**：IOCTL 全部實作、ABI 有測試、自我保護會推送、doctor 會回報。仍需已簽章的 driver 才會在真實機器上生效 |
| 2 | E→D | process 事件無 hash / signer | **已修**：Windows 走 enrichment（embedded + catalog 兩條簽章路徑），macOS 走 ES；`Hashes` 47 條與 `Signed` 15 條不再被欄位缺失擋住 |
| 8 | 測試 | 盲區 | **部分**：新增 26 個測試（driver ABI、quarantine、WFP 命名、enrichment、authenticode），rsigma pin 有防漂移檢查。kernel 側 C / eBPF 仍零測試 |
| 9 | R | quarantine clobber、isolate 疊加 | **已修**，各附回歸測試 |
| 3 | D | 內建規則僅 demo，覆蓋率繫於外部未簽章 repo | 未動 |
| 4 | R | Linux / macOS 無網路隔離與 persistence 動作 | 未動 |
| 5 | E | 無 backpressure、無 ETW session 恢復、無 file rundown | 未動 |
| 6 | D | 無行為 / 基線分析；correlation reload 即失 | 未動 |
| 7 | D | 單一告警通道、無 ATT&CK ECS 對應、IOC 只吃純文字 | 未動 |

## 文件已承認 vs 未提及

**已承認**（散見 [Limitations](limitations.md)、[Sigma Coverage](coverage.md)、[Active Response](active-response.md)、`driver/README.md`）：
無 backpressure、Security channel 依賴 audit policy、correlation reload 失憶、非商用 EDR 替代、driver 不出貨、
memory-only 與 LOLBin 難偵測、Linux / macOS 隔離缺席。

**原本未提及、本次已寫進文件**：driver executor 的實際狀態（`driver/README.md` 新增〈What the agent side does today〉）；
hash / signer 現況與其代價（`limitations.md`，含 `Imphash` 仍缺、catalog 無 publisher、簽章不做網路 revocation）；
`process.hash_images` 的成本取捨（`config.toml`）。

**仍未提及**：沒有 ETW session 恢復；單一告警通道；沒有 ATT&CK ECS 欄位；kernel 側 C / eBPF 零測試；
macOS response 只編譯不在 CI 執行。

## 方法與出處

三個面向各由一次獨立的唯讀程式碼審計完成（範圍：`src/sensor/**`、`ebpf/`、`driver/`、`src/engine/**`、`src/ioc/**`、`src/memory/**`、
`src/scanner`、`src/alerts`、`src/response/**`、`tests/`、`compatibility/`、既有 `docs/`），關鍵聲稱再以 `grep` / 原碼回查確認。
量測數字（Sigma 可載入 / 可觸發）直接引用 `compatibility/sigmahq-baseline.json` 與 `docs/coverage.md`，未重跑。
本文是時間點快照；collector、欄位對應、規則語料任一變動都會使數字移動。

---

## 本次變更

以修補缺口為目的的一輪改動，全部在 `feat/response-layer` 上：

| 缺口 | 改了什麼 | 驗證 |
|---|---|---|
| driver 死合約 | `src/response/executor/driver.rs` 全面重寫：`abi` 模組鏡射 `rustinel_ioctl.h`、四個 IOCTL 以 `DeviceIoControl` 實作、`protect_self()` 於啟動推送、`doctor` 新增 `response_driver_state` | 11 個測試，含 size / offset / CTL_CODE 逐項比對 |
| quarantine 覆寫 | `write_new` 改用 `create_new`；record id 與 content hash 分離；blob 共用並在最後一筆移除時才刪 | 回歸測試：同 bytes 兩個路徑 → 兩筆記錄、各自還原 |
| isolate 疊加 | isolate 在同一 transaction 內先移除自己的舊 filter；以 display name 前綴限定範圍 | 前綴關係 drift guard |
| 無 hash / signer | `ProcessCreationFields` / `ImageLoadFields` 新增 `Hashes` / `Signed` / `Signature` / `SignatureStatus`；Windows enrichment 計算並快取；`src/utils/authenticode.rs` 做 embedded + catalog 驗證；macOS 從 ES 取 cdhash / team id；ECS 補 `process.hash.*` 與 `process.code_signature.*` | 15 個測試，含對空檔已知摘要、catalog 簽章系統檔、竄改檔 |
| rsigma 版本偏差 | pin 0.18 → 0.21，並加 CI 檢查比對 `Cargo.toml` | 以實際檔案跑過 guard 邏輯 |
| macOS 看不見 persistence | `src/sensor/persistence.rs` 依 SentinelOne 指南第 1 章分類 11 類持久化位置，file 事件帶上 `PersistenceMechanism` | 8 個測試，含大小寫折疊與「檔名只是提到目錄」的規避案例 |
| Linux / macOS 無網路隔離 | `src/response/executor/host_firewall.rs`：Linux nftables、macOS pf。規則產生是純函式並全部測過，只有交給 `nft` / `pfctl` 的薄層碰到系統 | 11 個測試：policy drop 而非 drop rule、`inet` 表涵蓋 IPv6、established 雙向、loopback、前綴長度、pf 的 `quick` 順序 |
| Linux / macOS 無 persistence 動作 | `src/response/executor/unix_service.rs`：`systemctl disable --now` 與 `launchctl disable` + `bootout`；保護清單編譯期寫死 | 7 個測試，含 agent 自身與會讓操作者失去機器的單元一律拒絕 |
| macOS 看不見注入與憑證存取 | ES 訂閱加上 `trace` / `get_task` / `get_task_read` / `remote_thread_create`，對映到 ProcessAccess 與 RemoteThread，並用 Sysmon 的 event ID 8 / 10 | 7 個測試（`src/sensor/cross_process.rs`，在每個平台都跑） |
| Linux 看不見跨行程讀寫 | eBPF 新增 `sys_enter_ptrace`，經 process ring 以 `kind` 分派；與 macOS 共用同一組事件組裝 | ABI 斷言（大小 64、`kind` 與 `ProcessEvent` 同 offset）現在在 Windows 上也會編譯，已實測會擋下刻意注入的欄位漂移 |
| Linux 事件無 hash | `Enricher` 從 `sensor/windows/` 移到 `sensor/enrichment.rs`，三平台共用；PE 版本資源那一半留在 Windows | 移動後的 9 個測試現在在 Windows 與 Linux CI 都會跑 |

**驗證範圍**：581 個 lib 測試 + 30 個整合測試套件通過，`cargo clippy --all-targets` 與
`cargo fmt --check` 乾淨。

**本機驗證不到的部分，以及為此做的設計取捨**：本機是 Windows，連 macOS 的 target-specific
相依都抓不到，Linux 同理。所以新程式碼刻意把**會出錯的邏輯**與**碰系統的薄層**分開：

- 防火牆規則的產生是 `IsolationPolicy → String` 的純函式，在 Windows 上照樣編譯與測試
  （`nftables_ruleset` / `pf_ruleset`，11 個測試）。真正只在 Linux / macOS 跑的，是把字串
  餵給 `nft` / `pfctl` 的幾十行。
- persistence 分類與 cross-process 事件組裝放在 `src/sensor/` 而非 `src/sensor/macos/`，
  用的是既有 `integrity_level` 的 `#[cfg(any(..., test))]` 做法，所以規避案例與事件形狀
  在每個平台都會跑到，而不是只有 macOS runner 會編譯。
- eBPF 的 `PtraceEvent` 與使用者空間鏡像之間的 ABI 斷言，原本只在 Linux 編譯——也就是
  只有那台 runner 會發現不一致，而它已經把不一致跑起來了。現在 `sensor/linux/events.rs`
  的資料半部會在非 Linux 的測試組建中以別名編入，斷言因此在本機生效；
  刻意插入一個欄位確認過它會擋下來。
- 保護單元清單同樣是純比對，本機測得到。

**仍只由 CI 驗證**：`src/sensor/macos/esf.rs` 的 ES 欄位讀取（`cdhash` / `team_id` /
`codesigning_flags`），以及兩個 platform 模組的行程呼叫。API 形狀取自 docs.rs，不是編譯器。

## 要把剩下的格子補到 ●●●●● 需要什麼

誠實的估計，而不是把分數調高：

- **E 深度**：真正的 backpressure（目前只計數不阻擋，所以慢的 enrichment 會讓後面的事件被丟掉）、
  ETW session 重連、file rundown（冷啟動時 file-path 解析只有 1.2%）。
- **Linux E 廣度**：module load（BYOVD 的對應面）、inbound 連線與 `accept()`、DNS 回應。
  eBPF 掛載點都存在，缺的是程式與對映。
- **macOS E 廣度**：`mmap` / `mprotect`（記憶體階段）、登入與 `sudo` 事件、BTM launch item。
  `endpoint-sec` 目前釘在 `macos_11_0_0`，較新的事件要提高最低支援版本。
- **E 深度（Linux signer）**：Linux 沒有 Authenticode，signer 只能靠 IMA / dm-verity，
  能給的比 Windows 少；目前 Linux 只有 hash 沒有 signer。
- **R 廣度**：Linux/macOS 的 per-image 網路封鎖（nftables 只能比對 cgroup、pf 只能比對 user，
  兩者都不是「這個執行檔」，所以要先把行程放進 cgroup）、cron / launchd 排程項目的停用。
- **R inline**：macOS 的 ES **AUTH** 事件——不需要 kext 就能 inline 拒絕 exec 與 open，
  是三個平台裡唯一不需要簽章憑證就能做到 inline 阻擋的。代價是 AUTH 有回應期限，
  答得慢會卡住整台機器，所以它需要專門的期限與失效設計。
- **D**：行為 / 基線分析；correlation 狀態在 reload 後保留；ATT&CK 的 ECS 欄位對應；
  syslog / webhook 輸出；IOC 支援 STIX / CSV。
- **D 規則覆蓋 ●●○○○**：需要簽章的 rule catalog，以及把 atomic harness 納入本 repo 才量得到。
  這是唯一一個不靠寫程式就能解決的格子，也是目前最低的。
