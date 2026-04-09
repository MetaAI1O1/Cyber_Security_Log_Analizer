# 網路安全日誌分析工具 (Cyber Security Log Analyzer)

[English](#english-version) | [繁體中文](#繁體中文版本)

---

## 繁體中文版本

本專案提供一套完整的 Python 工具鏈，用於將多來源系統日誌正規化，並進行深度的安全威脅偵測、風險評分與自動化調查。

### 環境需求 / Requirements
- **Python 3.x**
- **pandas** (`pip install pandas`)

### 使用方法 / Usage
1.  將原始 CSV 日誌檔案放入 `RAW_DATA/` 目錄中。
2.  **執行全量分析**：
    ```bash
    python main.py
    ```
3.  **定向調查特定使用者**:
    ```bash
    python analyze_logs.py --user [使用者名稱]
    ```
4.  前往 `result/` 各分類資料夾查看產出的 10+ 項分析報表，特別是 `investigations/` 內的嫌疑人深度調查報告。

### 核心功能

1.  **自動化整合執行 (`main.py`)**:
    一鍵完成所有分析流程，包含日誌正規化與資安威脅偵測。
2.  **日誌正規化 (`normalize_logs.py`)**:
    將分散的原始日誌整合，產出以下策略檔案於 `result/`：
    - **時間軸策略 (Timeline Strategy)**: 統合所有事件至單一時間線。
    - **使用者行為策略 (User Activity Strategy)**: 以使用者為中心，彙整其數位足跡。
3.  **資安威脅分析 (`analyze_logs.py`)**:
    *   **風險評分系統 (Risk Scoring)**: 結合時間（非上班時間）、動作（壓縮/刪除）與資產敏感度進行權重計算。
    *   **多維度監控**:
        - **初始入侵偵測**: 電子郵件惡意附件篩選、暴力破解統計。
        - **執行與持續性監控**: 異常程序執行、程序偽裝行為辨識。
        - **流量與連線異常**: DNS 心跳信號偵測、資料外洩量化。
        - **目標行為分析**: 敏感檔案存取監控（包含非上班時間偵測與高風險動作評估）。
4.  **自動化調查引擎 [New]**:
    *   **自動模式**: 系統自動識別風險分數最高的前三名嫌疑人。
    *   **手動模式**: 支援透過命令列參數指定特定對象進行深度調查（`--user`）。
    *   **攻擊鏈重建**: 產出 `investigation_[user].csv`，整合登入、程序、檔案與 USB 所有事件並按秒排序。

### 目錄結構
- `RAW_DATA/`: 存放原始 CSV 日誌檔案。
- `result/`: 分類報表目錄：
  - `alerts/`: 存放關鍵資安告警（如：Critical File Access）。
  - `summaries/`: 存放統計摘要與風險排名（如：Top Risky Users）。
  - `investigations/`: **自動化產出的嫌疑人深度調查時間軸**。
  - `raw_analysis/`: 存放完整的初步過濾與分析數據。
- `main.py`: **整合執行進入點**。
- `analyze_logs.py`: 核心資安分析與動態調查邏輯。
- `normalize_logs.py`: 日誌格式統一與摘要邏輯。
- `Analyze_Strategy.md`: 詳細的分析清單與實作進度。

### 驗證資訊
- **總日誌處理量**: 108,000+ 筆
- **偵測範圍**: 涵蓋 Email, Auth, DNS, Endpoint, Firewall, Netflow, File, USB 等 8 類日誌。

---

## English Version

This project provides a comprehensive Python toolkit to normalize multi-source system logs and perform in-depth security threat detection, risk scoring, and automated investigation.

### Requirements
- **Python 3.x**
- **pandas** (`pip install pandas`)

### Usage
1.  Place the original CSV log files into the `RAW_DATA/` directory.
2.  Run the full analysis:
    ```bash
    python main.py
    ```
3.  **Targeted User Investigation [New]**:
    ```bash
    python analyze_logs.py --user [username]
    ```
4.  Check the `result/` subdirectories for categorized reports (10+ reports), especially the deep-dive investigation reports in `investigations/`.

### Core Features

1.  **Integrated Runner (`main.py`)**:
    Complete the entire analysis workflow with a single command, including normalization and threat detection.
2.  **Log Normalization (`normalize_logs.py`)**:
    Integrates scattered raw logs into strategic files:
    - **Timeline Strategy**: Unified chronological view of all events.
    - **User Activity Strategy**: Aggregated digital footprints centered around users.
3.  **Security Threat Analysis (`analyze_logs.py`)**:
    *   **Risk Scoring System**: Calculates threat levels based on off-hours access, high-risk actions (compress/delete), and asset sensitivity.
    *   **Multi-vector Monitoring**:
        - **Initial Access**: Email phishing/malicious attachment filtering, Brute Force statistics.
        - **Execution & Persistence**: Suspicious process execution, Process masquerading detection.
        - **Network Anomalies**: DNS beaconing detection, Data exfiltration quantification.
        - **Target Actions**: Sensitive file access monitoring.
4.  **Automated Investigation Engine [New]**:
    *   **Automatic Mode**: Identifies the Top 3 suspects based on risk scores.
    *   **Manual Mode**: Supports targeted investigation of specific users via CLI (`--user`).
    *   **Kill Chain Reconstruction**: Generates `investigation_[user].csv`, merging and sorting Login, Process, File, and USB events chronologically.

### Directory Structure
- `RAW_DATA/`: Source CSV log files.
- `result/`: Categorized reporting structure:
  - `alerts/`: Critical security alerts (e.g., Critical File Access).
  - `summaries/`: Statistical summaries and risk rankings (e.g., Top Risky Users).
  - `investigations/`: **Automated timeline reports for suspects.**
  - `raw_analysis/`: Full filtered analysis logs.
- `main.py`: **Main entry point**.
- `analyze_logs.py`: Core threat analysis and dynamic investigation logic.
- `normalize_logs.py`: Log normalization and summarization logic.
- `Analyze_Strategy.md`: Detailed analysis roadmap and implementation status.

### Validation
- **Total Log Volume**: 108,000+ records.
- **Detection Scope**: Covers 8 log types (Email, Auth, DNS, Endpoint, Firewall, Netflow, File, USB).
