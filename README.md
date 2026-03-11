# 日誌正規化工具 (Log Normalization Strategy Toolkit)

本專案提供 Python 腳本，依照不同的分析需求將系統日誌正規化。
This project provides a Python script to normalize system logs based on different analysis requirements.

## 正規化策略說明 / Normalization Strategies

### 1. 時間軸策略 (Timeline Strategy) -> `strategy_timeline.csv`
- **目的 (Purpose)**: 將所有分散的日誌整合成一個統一的時間軸。
  Integrate all scattered logs into a unified timeline.
- **優點 (Pros)**: 適用於事件回溯，查看特定時間點前後的連動行為。
  Ideal for incident retracing and analyzing sequence of events.
- **輸出包含 (Columns)**:
    - `timestamp`: 事件發生時間 / Event time.
    - `log_source`: 原始日誌類別 / Original log source.
    - `user`: 統合後的身分欄位 / Consolidated identity.

### 2. 使用者行為策略 (User Activity Strategy) -> `strategy_user_activity.csv`
- **目的 (Purpose)**: 以使用者為核心，彙整每位使用者的數位足跡。
  Summarize digital footprints for each user.
- **優點 (Pros)**: 適用於內部威脅分析與基準行為定義。
  Ideal for Insider Threat Detection and user profiling.
- **輸出包含 (Columns)**:
    - `user`: 使用者識別碼 / User ID.
    - `total_events`: 總事件數 / Total events.
    - `first_seen` / `last_seen`: 活躍時間範圍 / Activity timeframe.
    - `active_sources`: 使用過的服務 / Services used.
    - `primary_activities`: 最頻繁的動作 / Most frequent actions.
    - `active_days`: 活躍天數 / Days active.

## 環境需求 / Requirements
- Python 3.x
- pandas (`pip install pandas`)

## 使用方法 / Usage
1. 將原始 CSV 日誌檔案放入 `RAW_DATA/` 目錄中。
   Place raw CSV log files in the `RAW_DATA/` directory.
2. 執行 / Run: `python normalize_logs.py`
3. 獲取結果檔 / Get output files.

## 驗證資訊 / Validation
- 總日誌筆數 / Total logs: 108,000.
- 使用者總數 / Total users: 14.
