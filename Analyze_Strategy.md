# 日誌分析實作清單 / Log Analysis Implementation List

本清單專注於從原始日誌中提取安全威脅與異常行為。
This list focuses on extracting security threats and anomalies from raw logs.

## 1. 偵測初始入侵行為 (Detecting Initial Access)
*   [ ] **電子郵件威脅分析 (Email Threat Analysis)**:
    *   篩選 `email_logs.csv` 中的高風險關鍵字與惡意附檔名。
    *   Filter high-risk keywords and malicious attachments in `email_logs.csv`.
*   [ ] **登入失敗與暴力破解 (Login Failures & Brute Force)**:
    *   統計 `auth_logs.csv` 中的登入失敗次數與異常來源 IP。
    *   Count login failures and identify suspicious source IPs in `auth_logs.csv`.

## 2. 偵測執行與持續性行為 (Detecting Execution & Persistence)
*   [ ] **異常程序執行 (Suspicious Process Execution)**:
    *   從 `endpoint_logs.csv` 識別 PowerShell 或 CMD 的異常調用。
    *   Identify unusual calls to PowerShell or CMD from `endpoint_logs.csv`.
*   [ ] **程序行為比對 (Process Behavior Mapping)**:
    *   偵測程序名稱與執行內容不符的偽裝行為。
    *   Detect masquerading behaviors where process names mismatch their actions.

## 3. 偵測連線與流量異常 (Detecting C2 & Traffic Anomalies)
*   [ ] **DNS 查詢頻率分析 (DNS Query Frequency Analysis)**:
    *   識別 `dns_logs.csv` 中的心跳信號（Beaconing）。
    *   Identify heartbeats (Beaconing) in `dns_logs.csv`.
*   [ ] **異常外連流量 (Suspicious Outbound Traffic)**:
    *   在 `firewall_logs.csv` 與 `netflow_logs.csv` 中找出連向外部的高流量連線。
    *   Find high-volume connections to external IPs in `firewall` and `netflow` logs.

## 4. 偵測目標達成行為 (Detecting Actions on Objectives)
*   [ ] **敏感檔案存取監控 (Sensitive File Access Monitoring)**:
    *   分析 `file_logs.csv` 中針對機密文件（`.db`, `.txt`）的存取記錄。
    *   Analyze access records for confidential files in `file_logs.csv`.
*   [ ] **資料外洩量化 (Quantifying Data Exfiltration)**:
    *   從 `netflow_logs.csv` 計算每個主機的外傳總流量。
    *   Calculate total outbound traffic per host from `netflow_logs.csv`.
