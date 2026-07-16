# pwnscout 完整實戰教學（繁體中文）

> 離線、不接 AI、零依賴的攻擊面 / 可利用性掃描器。
> 帶去賽場，跑完就知道**有哪些洞可以打**、**為什麼可打**、**下一步指令是什麼**。

本教學對應 **v0.2.1**。所有指令、旗標都與工具實際行為一致。

---

## 目錄

1. [設計理念與心智模型](#1-設計理念與心智模型)
2. [安裝與帶去賽場](#2-安裝與帶去賽場)
3. [看懂排序報告（attack score）](#3-看懂排序報告attack-score)
4. [`scan` — 網路面偵查](#4-scan--網路面偵查)
5. [`web` — Web 紅隊主戰場](#5-web--web-紅隊主戰場)
6. [`exploit` — A/D 批量利用](#6-exploit--ad-批量利用)
7. [`kb` — 知識庫與擴充](#7-kb--知識庫與擴充)
8. [實戰劇本](#8-實戰劇本)
9. [賽場一頁小抄](#9-賽場一頁小抄)
10. [道德與法律](#10-道德與法律)

---

## 1. 設計理念與心智模型

pwnscout 只做一件事，並把它做到最好：**在最短時間內，把「一堆 IP / 一個網站」變成「一張可以照著打的優先清單」**。

四個原則：

- **離線、決定性**：純 Python 標準庫，不連雲端、不接 AI、不 phone home。同輸入 → 同輸出。
- **可行動**：每條發現都帶 `why`（為什麼可打）＋ `next_step`（可貼上就跑的指令）。
- **排序**：單一 0–100 的 attack score，讀報告由上往下打即可。
- **會確認**：`--verify` 與 web 主動探測會用**安全、唯讀**的 PoC，把「可能有」變成「✓verified」。

四個子指令（心智模型）：

| 指令 | 打什麼 | 一句話 |
|------|--------|--------|
| `scan` | 網路面（IP / 網段 / 服務） | 埠掃 → 服務指紋 → 版本對 CVE → 安全 PoC 確認 |
| `web`  | 單一 Web 應用 | 爬蟲 → 內容爆破 → 主動漏洞探測 → 登入 → JWT → IDOR → 產生利用 |
| `exploit` | A/D 批量 | 把你的 exploit 模組對全場敵隊併發開火、抓旗、交旗 |
| `kb`   | — | 看載入了哪些知識庫、偵測到哪些外部工具 |

---

## 2. 安裝與帶去賽場

**零安裝，clone 就跑（最推薦帶去現場）：**

```bash
git clone https://github.com/ericchen913900/pwnscout.git
cd pwnscout
python3 pwnscout.py --version      # 只要有 python3 就能動
```

**或裝成指令：**

```bash
pip install .        # 提供 `pwnscout` 指令
pwnscout --version
```

需求：**Python 3.8+，零第三方套件**。這是刻意的——賽場常常是一台被鎖死、沒網路的機器。

**選用的外部工具**（有就自動用、沒有就用純 Python fallback）：`nmap`、`smbclient`、`searchsploit`、`redis-cli`、`git-dumper`。用 `python3 pwnscout.py kb` 看現場偵測到哪些。

---

## 3. 看懂排序報告（attack score）

每條發現的分數是**決定性**算出來的：

```
score = 嚴重度權重 × 信心倍率   (+10 已驗證, +5 已知可利用)
```

- **嚴重度**：info → low → medium → high → critical
- **信心**：
  - `possible` — 只靠版本 / banner 推斷（可能誤報）
  - `likely` — 有明確、具體的訊號
  - `confirmed` — 安全 PoC 實際證明了（報告會標 `✓verified`）

由高到低排 = 你的待辦清單。終端機報告長這樣：

```
100 ██████████ [CRIT] 10.0.0.5:8080  Server-Side Template Injection (param 'q') ✓verified
     why: Template expression was evaluated (Jinja2) — this is typically RCE.
     run: curl -s 'http://10.0.0.5:8080/search?q=pwnss%7B%7B7%2A7%7D%7D'
```

### 3.1 風險等級（CVSS）與「可提交」

每條發現除了 attack score，還會算一個 **CVSS 3.1 風險評分**（真的用公式算出向量＋分數）與風險等級（None/Low/Medium/High/Critical）。終端機報告會顯示 `CVSS x.x`，並在「值得提交」的發現前面標 **★**：

```
★ 100 [CRIT] SSTI (param 'q') ✓  CVSS 9.8
```

**可提交（submittable）** 的判定：CVSS ≥ 4.0、已確認或高信心、且屬於真正的漏洞類別。純 recon 線索（例如「/admin 可達」、JWT 沒有 exp）會被降為 informational，**不會灌進可提交清單**。CVSS 是**依漏洞類別估算**的，提交前請自己再看一眼。

### 3.2 `-o` 一下 = 完整可交付成果（報告 ＋ PoC）

只要加 `-o <名字>`，`scan` / `web` 都會產出一整包**可直接交的成果**：

```bash
python3 pwnscout.py web http://target/ --discover -o loot/target
```

- `loot/target.md` / `.html` — **漏洞報告**：每條含 CVSS 向量＋分數、風險、信心、受影響資產、描述、**重現步驟**、PoC 指標、影響、**修補建議**
- `loot/target.json` — 機器可讀，每條加了 `cvss_vector`/`cvss_score`/`risk`/`submittable`/`remediation`
- `loot/target_pocs/` — **PoC 包**：已確認的 SSTI/LFI/SQLi 產生可跑的 `Module(Exploit)`、其餘產生重現腳本，加 `POC_INDEX.md`（風險/CVSS/檔案對照表）與 `EXPLOIT_PLAN.md`

換句話說：**一掃下去就有 PoC ＋ 分好風險等級的漏洞報告，還標好哪些可以提交。**

**Exit code（給 CI / 腳本）**：`0` = 無 high/critical；`2` = 有 high/critical；`1` = 用法錯誤。

---

## 4. `scan` — 網路面偵查

```bash
python3 pwnscout.py scan <目標...> [選項]
```

**目標格式**：`10.10.10.5`、`10.10.10.0/24`、`10.10.10.5-40`、主機名、`@targets.txt`、或直接給檔案路徑。

**常用範例：**

```bash
# 網段快掃（top 埠），列出可打的洞
python3 pwnscout.py scan 10.10.10.0/24

# 單機全埠 + 安全 PoC 確認 + 存報告
python3 pwnscout.py scan 10.10.10.5 --profile full --verify -o loot/box5

# 只看高價值（分數 ≥ 50）
python3 pwnscout.py scan 10.10.10.0/24 --min-score 50

# 現場有 nmap 就用它做版本偵測（更準）
python3 pwnscout.py scan targets.txt --nmap --verify

# 也試少量預設帳密（HTTP Basic / Tomcat）
python3 pwnscout.py scan 10.10.10.7 -p 8080,8443 --verify --brute
```

**重要旗標：**

| 旗標 | 作用 |
|------|------|
| `-p 80,443,8000-8100` | 指定埠（覆蓋 `--profile`） |
| `--profile top\|web\|full` | 埠集合（預設 top，114 個精選埠；full = 1–65535） |
| `--verify` | 跑安全唯讀 PoC：匿名 FTP、未授權 Redis/Docker/ES/Memcached/Mongo、SMB null session、暴露的 `.git`/`.env` |
| `--brute` | 額外試極少量預設帳密（避免鎖帳號） |
| `--nmap` | 有裝就用 `nmap -sV` 補強版本 |
| `--concurrency` / `--timeout` | 埠掃併發 / 連線逾時 |
| `-o 前綴` | 輸出 json/md/html |
| `--min-score N` / `--top N` | 過濾 / 只看前 N 條 |

**它會做的檢查**：埠掃 → 服務/版本指紋 → 版本對 CVE（vsftpd 2.3.4 後門、ProFTPD mod_copy、Apache 2.4.49/2.4.50 穿越、SambaCry、IIS6 WebDAV、Exim、Elasticsearch Groovy…）＋ 埠層提示（MS17-010 / BlueKeep / Ghostcat / 暴露的 Docker/NFS/SNMP/LDAP）→ 輕量 HTTP 指紋與敏感路徑 → `--verify` 安全確認。

---

## 5. `web` — Web 紅隊主戰場

這是紅隊打 web 的核心。點一個網站，它會：**爬蟲測繪 → 內容爆破 → 主動漏洞探測 → （選）自動登入 → JWT → 存取控制/IDOR → （選）產生利用**，全部進同一張排序報告。

```bash
python3 pwnscout.py web <網址...> [選項]
```

### 5.1 基本

```bash
# 爬蟲 + 主動探測
python3 pwnscout.py web http://target/

# 加內容爆破 + 存報告
python3 pwnscout.py web http://target/ --discover -o loot/app
```

爬蟲（同源、預設深度 2）會測繪出 URL、表單、以及**可注入點**（GET 參數與表單欄位），這些注入點就是後面主動探測的攻擊面。

### 5.2 主動漏洞探測（全部「只偵測、不破壞」）

| 探測 | 怎麼判定（安全手法） | 命中代表 |
|------|--------------------|---------|
| 反射型 XSS | canary 特殊字元原樣回顯 | HIGH，去湊可用 payload |
| **SSTI** | `{{7*7}}`/`${7*7}`/… 被求值成 `49`（會標引擎） | **CRIT，通常＝RCE** |
| error-based SQLi | 單引號觸發 DB 錯誤、乾淨請求沒有 | HIGH |
| 路徑穿越 / LFI | payload 回傳 `/etc/passwd`、`win.ini` 標記 | HIGH |
| Open Redirect | 導向參數把你送到外部標記網域 | MED |
| CORS | `Origin` 被反射且允許帶憑證 | MED |
| 標頭 / Cookie | 缺 CSP/HSTS/nosniff/frame-options、Cookie 缺 HttpOnly/Secure/SameSite | LOW |

**安全界線**：不發時間盲注、不外洩資料、不改狀態。命中＝「這裡可打，去手動確認利用」，報告給你重現指令。

用 `--no-probe` 只做爬蟲/爆破；用 `--max-points`（預設 40）與 `--probe-budget`（預設 1500 次請求）限制規模——**打滿會明確告訴你沒測完**，不會靜默少測。

### 5.3 內容 / 目錄爆破

```bash
python3 pwnscout.py web http://target/ --discover
python3 pwnscout.py web http://target/ --discover --wordlist ~/SecLists/.../raft-medium-directories.txt
python3 pwnscout.py web http://target/ --discover --ext php,bak,txt,zip
```

- 內建 254 條高訊號字典；`--wordlist` 換成 SecLists 做更深的掃描。
- 帶 soft-404 基準線去誤報；敏感命中（admin/.git/backup/403…）獨立列成 finding。

### 5.4 認證掃描（自動登入）

給登入頁＋帳密，自動偵測表單（含隱藏 CSRF token）、登入、cookie jar 接管 session，之後**整個爬蟲＋探測都以登入身分進行**。

```bash
# 自動偵測欄位
python3 pwnscout.py web http://target/ \
  --login-url http://target/login --login-user admin --login-pass secret

# 直接給原始欄位 / 用字串確認登入成功
python3 pwnscout.py web http://target/ \
  --login-url http://target/login --login-data 'user=admin&pass=secret' \
  --login-check 'Logout'
```

若你已經有 cookie / API key，也可直接帶：

```bash
python3 pwnscout.py web https://target/ --cookie "session=eyJ..." --header "X-Api-Key: abc"
python3 pwnscout.py web https://target/ --auth-basic admin:admin
```

### 5.5 JWT 弱點（預設開啟）

從回應 / cookie / header 抓到的 JWT 會被解碼並檢查：
- **弱 HMAC 密鑰**（對內建字典離線爆破，破了就能偽造任意身分 → CRIT）
- `alg=none`、RS/ES→HS 演算法混淆、缺 `exp`、敏感 claim（role/admin…）

```bash
python3 pwnscout.py web http://target/ --jwt-wordlist ~/SecLists/.../jwt.secrets.list
python3 pwnscout.py web http://target/ --no-jwt      # 關掉
```

### 5.6 存取控制 / IDOR（預設開啟，需要 session）

登入後比對存取差異，抓授權破綻：
- **認證 vs 未認證**：登入才到的資源，用乾淨無 cookie session 再要一次；照樣回 200（沒被導去登入 / 401 / 403）→ 缺授權
- **數字 ID 鄰居**：物件參數 `id` 試 ±1，與「不存在的 ID」基準比對 → 可枚舉別人的物件（反射型參數會自動跳過，不誤報）
- **跨使用者**（`--cookie2` 第二帳號）：B 的 session 讀 A 的資源 → 水平越權

```bash
python3 pwnscout.py web http://target/ \
  --login-url http://target/login --login-user a --login-pass a \
  --cookie2 "session=<B的cookie>"
python3 pwnscout.py web http://target/ --no-idor       # 關掉
```

### 5.7 產生利用（`--gen-exploits`）—— 串到 A/D runner

把已確認的注入自動變成可跑的檔案：

```bash
python3 pwnscout.py web http://target/ --gen-exploits loot/exploits
```

每個確認的洞產生：
- **SSTI** → 依偵測到的引擎產生 RCE payload 的 `Module(Exploit)`
- **LFI** → 任意讀檔的 `Module(Exploit)`
- **SQLi** → 現成 sqlmap 交接腳本
- ＋ `EXPLOIT_PLAN.md`

產物可獨立跑（`python3 01_ssti_*.py <host> id`）或直接餵給 `exploit` runner 打全場（見 §6）。

### 5.8 過 WAF / 限速

```bash
python3 pwnscout.py web http://target/ --delay 0.3 --probe-budget 800 --max-points 20
```

`--delay` 每次請求之間睡幾秒；`--probe-budget`/`--max-points` 縮小主動探測規模。

---

## 6. `exploit` — A/D 批量利用

把「一個 exploit 模組」對「一堆敵隊 IP」併發開火、抓旗、（選）自動交旗，可 `--loop` 每回合重跑。

```bash
python3 pwnscout.py exploit <模組.py> --targets <IP...|@file> [選項]
```

### 6.1 寫一個模組

```python
# acme.py
from pwnscout.exploit import Exploit

class Module(Exploit):
    name = "acme-rce"
    description = "打某服務、把 flag 抓回來"
    default_port = 8080

    def run(self, target, ctx):
        # target = "10.0.0.5"，ctx 有 port / flag_regex
        # ... 你的 exploit ...
        return self.find_flag(loot_text, ctx)   # 回傳 flag 字串，或 None
```

### 6.2 開火

```bash
# 打一次
python3 pwnscout.py exploit acme.py --targets enemies.txt --port 8080

# A/D 每 30 秒一回合，抓到就自動交旗
python3 pwnscout.py exploit acme.py --targets enemies.txt --loop 30 \
  --submit-url https://scoreboard/flag
```

| 旗標 | 作用 |
|------|------|
| `--targets` | IP 清單或 `@file` |
| `--port` | 覆蓋模組的 `default_port` |
| `--threads` | 併發數 |
| `--flag-regex` | 自訂 flag 抽取正則 |
| `--submit-url` | 把抓到的 flag POST 過去（欄位名 `flag`） |
| `--loop N` | 每 N 秒重跑一回合（0 = 只跑一次） |

### 6.3 直接用 `--gen-exploits` 的產物

```bash
python3 pwnscout.py web http://mybox/ --gen-exploits ex/       # 在自己那台找洞、產生模組
python3 pwnscout.py exploit ex/01_ssti_*.py --targets enemies.txt --loop 30 --submit-url ...
```

`find_flag` 預設抓 `WORD{...}` 格式；A/D 想抓特定路徑的旗，SSTI 模組可用 `ctx['cmd']`（例如 `cat /flag`），LFI 模組可用 `ctx['file']`（例如 `/flag`）。

---

## 7. `kb` — 知識庫與擴充

```bash
python3 pwnscout.py kb
```

會列出載入的知識庫數量（vulndb / http 路徑 / 指紋 / 預設帳密 / web 字典 / JWT 密鑰 / payload）以及偵測到的外部工具。

**所有知識庫都是純檔案，可擴充：**

| 檔案 | 驅動什麼 |
|------|----------|
| `pwnscout/kb/vulndb.json` | banner/版本 → 已知 CVE ＋ 利用指引 |
| `pwnscout/kb/http_paths.json` | 敏感路徑探測（`.git`、`.env`、actuator、swagger…） |
| `pwnscout/kb/fingerprints.json` | web 應用指紋（Tomcat、Jenkins、GitLab、Confluence…） |
| `pwnscout/kb/payloads.json` | XSS/SSTI/SQLi/穿越/redirect/CORS 的 payload 與偵測特徵 |
| `pwnscout/kb/default_creds.json` | `--brute` 用的預設帳密 |
| `pwnscout/kb/web_wordlist.txt` | 內容爆破字典 |
| `pwnscout/kb/jwt_secrets.txt` | JWT HMAC 弱密鑰字典 |

**不改內建、疊加你自己的**：把同名 JSON 檔放進一個資料夾，用 `$PWNSCOUT_KB` 指過去，會**疊在內建之上**：

```bash
PWNSCOUT_KB=~/my-kb python3 pwnscout.py scan 10.0.0.0/24
```

**vulndb 條目範例**（加一個你要打的服務版本）：

```json
{
  "id": "myapp-1.2-rce",
  "match": {"product": "MyApp", "version_lt": "1.3"},
  "cve": "CVE-2026-xxxx",
  "title": "MyApp < 1.3 unauth RCE",
  "severity": "critical",
  "tags": ["rce", "unauth"],
  "why": "為什麼可打…",
  "next_step": "curl -s '{scheme}://{ip}:{port}/exploit'",
  "refs": ["https://..."]
}
```

`match` 支援 `product`（子字串/正則）、`version`/`version_lt`/`version_le`/`version_ge`/`version_gt`/`version_regex`、`port`、`banner_regex`。`next_step` 內可用 `{ip} {host} {port} {scheme} {base}`（其他大括號不會被動到，payload 可原樣保留）。

---

## 8. 實戰劇本

### 劇本 A — 拿到一個網段（jeopardy / boot2root）

```bash
# 1) 全網段掃、確認、存檔
python3 pwnscout.py scan 10.10.10.0/24 --verify -o loot/net

# 2) 挑高分主機，對它的 web 埠深掃
python3 pwnscout.py web http://10.10.10.7:8080/ --discover -o loot/box7

# 3) 照報告最上面那條的 next_step 打；有 SSTI/LFI 就產生模組
python3 pwnscout.py web http://10.10.10.7:8080/ --gen-exploits loot/box7-ex
```

### 劇本 B — 一個 Web 應用（bug bounty 式，已授權）

```bash
# 登入 + 全套探測 + 內容爆破 + 產生利用
python3 pwnscout.py web https://app.target/ \
  --login-url https://app.target/login --login-user me --login-pass pw \
  --discover --wordlist ~/SecLists/.../raft-medium-directories.txt \
  --gen-exploits loot/ex --delay 0.2 -o loot/app

# 有第二個測試帳號就順便測跨使用者 IDOR
python3 pwnscout.py web https://app.target/ \
  --login-url https://app.target/login --login-user me --login-pass pw \
  --cookie2 "session=<第二帳號cookie>"
```

讀報告：SSTI/SQLi/LFI 先打（分數最高）→ IDOR / 缺授權 → JWT → XSS/CORS/標頭。

### 劇本 C — Attack / Defense

```bash
# 1) 在自己那台（跟敵隊同一份服務）找洞、產生利用模組
python3 pwnscout.py web http://127.0.0.1:PORT/ --gen-exploits ad-ex/

# 2) 準備敵隊 IP 清單
printf '10.0.%d.1\n' $(seq 1 30) > enemies.txt

# 3) 對全場每 30 秒開火、自動交旗（SSTI 模組抓 /flag）
python3 pwnscout.py exploit ad-ex/01_ssti_*.py \
  --targets @enemies.txt --loop 30 --submit-url http://scoreboard/submit
# 若旗在檔案：編輯模組把 CMD 改成 "cat /flag"，或用 LFI 模組 --file /flag
```

同時別忘了防守：對自己的服務也跑一次 `web`，把報告最上面那些洞先補掉。

---

## 9. 賽場一頁小抄

```bash
# 環境檢查
python3 pwnscout.py kb

# 網段快掃 → 高分優先
python3 pwnscout.py scan 10.0.0.0/24 --verify --min-score 50

# 單一 web app 全套（登入 + 爆破 + 產生利用）
python3 pwnscout.py web http://t/ --login-url http://t/login \
  --login-user u --login-pass p --discover --gen-exploits ex/ -o out

# 只要爬蟲/攻擊面、先不主動打
python3 pwnscout.py web http://t/ --no-probe --no-jwt --no-idor

# 過 WAF
python3 pwnscout.py web http://t/ --delay 0.5 --probe-budget 600 --max-points 15

# A/D 批量開火
python3 pwnscout.py exploit ex/01_*.py --targets @enemies.txt --loop 30 --submit-url URL

# 疊加自己的 KB
PWNSCOUT_KB=~/my-kb python3 pwnscout.py scan ...
```

**判讀口訣**：分數高的先打 → `✓verified` 最可靠 → 照 `run:` 那行貼上去驗證 → SSTI/SQLi/LFI 直接 `--gen-exploits` 串 A/D。

---

## 10. 道德與法律

pwnscout 只能用在**你擁有、或已取得明確書面授權**的系統（CTF 競賽、實驗靶場、授權滲透案、bug bounty 範圍內）。

- 未授權掃描 / 利用在多數司法管轄區屬刑事犯罪，你要為留在範圍內負全責。
- `--verify` 與 web 主動探測是**唯讀**的（不改目標狀態）；真正的利用（`--gen-exploits` 產物、`exploit` runner）是你主動、刻意的動作，請只對授權目標執行。
- 用 `--delay` / `--probe-budget` 控制流量，別把目標打掛。

祝賽場順利，跑完就知道有哪些洞可以打。
