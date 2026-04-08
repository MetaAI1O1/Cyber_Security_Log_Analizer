import pandas as pd
import glob
import os

def normalize_logs():
    """
    正規化日誌並產出兩種分析策略檔案。
    Normalize logs and generate two analysis strategy files.
    """
    
    # 尋找 RAW_DATA 目錄下所有的 csv 檔案
    # Find all CSV files in the 'RAW_DATA' directory
    csv_files = glob.glob('RAW_DATA/*.csv')
    
    # 定義輸出檔名
    # Define output filenames
    if not os.path.exists('result'):
        os.makedirs('result')
    output_timeline = 'result/strategy_timeline.csv'
    output_user_activity = 'result/strategy_user_activity.csv'
    
    # 排除可能已經產生的結果檔案
    # Exclude output files if they already exist in the directory
    output_files = [output_timeline, output_user_activity]
    for f in output_files:
        if f in csv_files:
            csv_files.remove(f)
            
    all_dataframes = []
    
    print(f"--- 正在讀取並處理檔案 / Reading and processing files ---")
    print(f"Files: {csv_files}\n")
    
    for file in csv_files:
        df = pd.read_csv(file)
        # 從路徑中擷取檔名作為來源標籤
        # Extract filename from path as source label
        source_name = os.path.splitext(os.path.basename(file))[0]
        
        # 加入來源標籤
        # Add source label
        df['log_source'] = source_name
        
        # 確保 timestamp 為 datetime 格式
        # Ensure timestamp is in datetime format
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # 正規化使用者欄位：整合電子郵件的 sender
        # Normalize user field: Integrate 'sender' from email logs
        if source_name == 'email_logs' and 'sender' in df.columns:
            df['user'] = df['sender']
            
        all_dataframes.append(df)
            
    if not all_dataframes:
        print("[錯誤/Error] 未找到任何日誌檔案。/ No log files found.")
        return

    # 策略一：全域時間軸日誌 (Timeline Strategy)
    # Strategy 1: Global Timeline Log
    combined_df = pd.concat(all_dataframes, ignore_index=True)
    combined_df = combined_df.sort_values(by='timestamp').reset_index(drop=True)
    combined_df.to_csv(output_timeline, index=False)
    print(f"[完成/Success] 已產出時間軸正規化結果 / Timeline normalization result generated: {output_timeline}")
    print(f"Total records: {len(combined_df)}\n")

    # 策略二：使用者行為摘要 (User Activity Strategy)
    # Strategy 2: User Activity Summary
    if 'user' in combined_df.columns:
        user_df = combined_df.dropna(subset=['user']).copy()
        
        user_summary = user_df.groupby('user').agg(
            total_events=('timestamp', 'count'),
            first_seen=('timestamp', 'min'),
            last_seen=('timestamp', 'max'),
            active_sources=('log_source', lambda x: ', '.join(sorted(x.unique()))),
            primary_activities=('action', lambda x: x.value_counts().index[0] if not x.dropna().empty else 'N/A')
        ).reset_index()
        
        # 計算活躍天數
        # Calculate active days
        user_summary['active_days'] = (user_summary['last_seen'] - user_summary['first_seen']).dt.days + 1
        
        # 依照事件總數排序
        # Sort by total events
        user_summary = user_summary.sort_values(by='total_events', ascending=False)
        
        user_summary.to_csv(output_user_activity, index=False)
        print(f"[完成/Success] 已產出使用者行為正規化結果 / User activity normalization result generated: {output_user_activity}")
        print(f"Total users: {len(user_summary)}")
    else:
        print("[警告/Warning] 找不到 'user' 欄位，無法產出摘要。/ 'user' column not found, skipping summary.")

if __name__ == "__main__":
    normalize_logs()
