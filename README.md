# YARA Rule Searcher

快速搜尋 [YARA Forge](https://github.com/YARAHQ/yara-forge/releases) 最新釋出的 YARA 規則，一鍵複製，並可在內建編輯器中修改後再複製使用。

所有規則都預先下載到網站的 `data/` 目錄，搜尋完全在瀏覽器本地端進行，不需要後端，也不會把查詢內容送到任何伺服器。

## 功能

- **即時搜尋**：規則名稱、描述、作者、標籤、來源專案、規則 ID；可選擇一併搜尋規則內容（字串、條件）。
- **雜湊反查**：輸入 MD5／SHA1／SHA256，自動找出 meta 中記錄該樣本雜湊的規則。
- **篩選與排序**：Core／Extended／Full 套件、來源專案、最低分數；依相關度、分數、修改日期或名稱排序。
- **一鍵複製**：自動附上該規則需要的 `import`（pe、elf、math…）與相依的 private 規則，複製下來即可直接編譯。
- **規則編輯器**：語法著色、行號、Tab／Shift+Tab 縮排、Enter 自動縮排、Ctrl+/ 註解、Ctrl+D 複製整行、尋找與取代、復原（Ctrl+Z）。
- **語法檢查**：大括號平衡、缺少 condition、重複規則或字串名稱、未使用的字串、未定義的字串、缺少 import、引用了不在編輯器內的規則等；部分問題可一鍵修正。
- **日間／夜間模式**：預設跟隨系統，可手動切換並記住選擇。
- **深層連結**：`#/rule/<規則名稱>` 可直接分享某條規則。
- **下載**：單條規則、整批搜尋結果或編輯後的內容皆可下載成 `.yar`。
- **自動更新**：GitHub Actions 每天檢查 YARA Forge 是否有新版，有的話自動更新資料並重新部署。

## 部署到 GitHub

```bash
# 1. 解壓縮後進入資料夾
cd yara-rule-searcher

# 2. 初始化並推送（把 <你的帳號> 換成你的 GitHub 帳號，並先在 GitHub 建立空的 yara-rule-searcher repo）
git init
git add .
git commit -m "init: YARA Rule Searcher"
git branch -M main
git remote add origin https://github.com/<你的帳號>/yara-rule-searcher.git
git push -u origin main
```

3. 到 repo 的 **Settings → Pages**，把 **Source** 設為 **GitHub Actions**。
4. 到 **Settings → Actions → General → Workflow permissions**，選 **Read and write permissions** 後儲存（讓排程能提交規則更新）。
5. 到 **Actions** 分頁，手動執行一次「更新 YARA Forge 規則並部署 GitHub Pages」（或等第一次 push 觸發的部署完成）。
6. 完成後網站位於 `https://<你的帳號>.github.io/yara-rule-searcher/`。

> `data/yara-db.js` 約 29 MB，低於 GitHub 單檔 50 MB 的警告門檻，不需要 Git LFS。

## 本地預覽

直接用瀏覽器開啟 `index.html` 即可（資料檔是 `.js`，`file://` 也能載入）。
若想用本地伺服器：

```bash
python3 -m http.server 8000
# 開啟 http://localhost:8000
```

## 手動更新規則

只需 Python 3.8 以上，不用安裝任何套件：

```bash
python3 scripts/build_db.py            # 抓最新版；已是最新則略過
python3 scripts/build_db.py --force    # 強制重建
python3 scripts/build_db.py --tag 20260927   # 指定版本
```

產生離線單檔版（規則以 gzip 內嵌，約 6 MB，可帶進隔離網路使用）：

```bash
python3 scripts/build_standalone.py    # 輸出 dist/yara-rule-searcher-standalone.html
```

## 搜尋語法

| 語法 | 說明 |
| --- | --- |
| `cobalt beacon` | 多個關鍵字需全部符合 |
| `"sleep mask"` | 以引號包住片語 |
| `repo:LOLDrivers` | 來源專案 |
| `author:"Florian Roth"` | 作者 |
| `tag:MEMORY` | 規則標籤 |
| `name:Emotet` | 只比對規則名稱 |
| `desc:loader` | 只比對描述 |
| `mod:dotnet` | 使用的 YARA 模組 |
| `score>=80`、`quality>=70` | 分數條件 |
| `-webshell` | 排除 |

鍵盤：`/` 聚焦搜尋框、`↑` `↓` 切換結果、`Esc` 清除搜尋。

## 專案結構

```
.
├── index.html                  # 頁面
├── assets/
│   ├── style.css               # 樣式（日／夜兩套色彩）
│   ├── yara-lang.js            # YARA 斷詞、語法著色、語法檢查
│   └── app.js                  # 搜尋、詳細資料、編輯器
├── data/
│   ├── yara-db.js              # 由 build_db.py 產生的規則資料庫
│   └── version.json            # 目前資料版本
├── scripts/
│   ├── build_db.py             # 下載並解析 YARA Forge release
│   └── build_standalone.py     # 產生離線單檔版
└── .github/workflows/pages.yml # 每日檢查更新與部署
```

## 授權與致謝

- 網站程式碼採 MIT 授權。
- 規則來自 [YARA Forge](https://github.com/YARAHQ/yara-forge)（由 Florian Roth 等人維護），彙整自 40 個開源規則專案。每條規則依其來源專案的授權使用，詳見規則 meta 的 `license_url`，以及網站右上角「資料來源與授權」。
- 編輯器的語法檢查為瀏覽器端的輕量檢查；正式部署前請以 `yara` 或 `yarac` 編譯驗證。
