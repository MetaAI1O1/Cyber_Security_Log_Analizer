import pandas as pd
import os
import argparse

# --- Helper: Directory Management ---
def ensure_dirs():
    """Create organized result directory structure."""
    base_dirs = [
        'result/summaries',
        'result/alerts',
        'result/investigations',
        'result/raw_analysis'
    ]
    for d in base_dirs:
        os.makedirs(d, exist_ok=True)
    return base_dirs

def analyze_email_threats():
    print("Analyzing Email Threats...")
    try:
        df = pd.read_csv('RAW_DATA/email_logs.csv')
        malicious_exts = ['.exe', '.scr', '.bat', '.js', '.vbs', '.ps1', '.zip']
        keywords = ['urgent', 'invoice', 'malicious', 'password', 'login', 'account']
        
        suspicious_attachments = df[df['attachment'].str.endswith(tuple(malicious_exts), na=False)]
        suspicious_subjects = df[df['subject'].str.contains('|'.join(keywords), case=False, na=False)]
        
        result = pd.concat([suspicious_attachments, suspicious_subjects]).drop_duplicates()
        result.to_csv('result/raw_analysis/email_threats.csv', index=False)
        print(f"  - Results saved to result/raw_analysis/email_threats.csv")
    except Exception as e:
        print(f"  - Error in Email Analysis: {e}")

def analyze_brute_force():
    print("Analyzing Login Failures & Brute Force...")
    try:
        df = pd.read_csv('RAW_DATA/auth_logs.csv')
        failed_logins = df[df['action'] == 'failed_login']
        
        brute_force_stats = failed_logins.groupby(['ip', 'user']).size().reset_index(name='failure_count')
        brute_force_stats = brute_force_stats.sort_values(by='failure_count', ascending=False)
        
        brute_force_stats.to_csv('result/summaries/brute_force_summary.csv', index=False)
        print(f"  - Results saved to result/summaries/brute_force_summary.csv")
    except Exception as e:
        print(f"  - Error in Brute Force Analysis: {e}")

def analyze_suspicious_processes():
    print("Analyzing Suspicious Process Execution...")
    try:
        df = pd.read_csv('RAW_DATA/endpoint_logs.csv')
        suspicious = df[
            (df['event'] == 'powershell') | 
            (df['detail'].str.contains('cmd.exe|powershell.exe|bash.exe|sh.exe', case=False, na=False))
        ]
        suspicious.to_csv('result/alerts/suspicious_processes.csv', index=False)
        print(f"  - Results saved to result/alerts/suspicious_processes.csv")
    except Exception as e:
        print(f"  - Error in Process Analysis: {e}")

def analyze_sensitive_file_access():
    print("Analyzing Sensitive File Access (Enhanced)...")
    try:
        df = pd.read_csv('RAW_DATA/file_logs.csv')
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        sensitive_ext = ('.db', '.tar', '.zip', '.sql', '.txt', '.xlsx', '.bak')
        is_sensitive = (df['sensitivity'].isin(['high', 'medium'])) | \
                       (df['filename'].str.endswith(sensitive_ext, na=False))
        
        sensitive_df = df[is_sensitive].copy()
        sensitive_df['is_after_hours'] = sensitive_df['timestamp'].dt.hour.isin([22, 23, 0, 1, 2, 3, 4, 5])
        sensitive_df['is_high_risk_action'] = sensitive_df['action'].isin(['compress', 'delete', 'modify'])

        # Risk Scoring
        sensitive_df['risk_score'] = 10 
        sensitive_df.loc[sensitive_df['is_high_risk_action'], 'risk_score'] += 20
        sensitive_df.loc[sensitive_df['is_after_hours'], 'risk_score'] += 30
        sensitive_df.loc[sensitive_df['sensitivity'] == 'high', 'risk_score'] += 40

        sensitive_df = sensitive_df.sort_values(by='risk_score', ascending=False)
        sensitive_df.to_csv('result/raw_analysis/full_file_access_analysis.csv', index=False)
        
        # 1. Critical Alerts Report
        critical_alerts = sensitive_df[sensitive_df['risk_score'] >= 70][
            ['timestamp', 'user', 'filename', 'action', 'risk_score']
        ]
        critical_alerts.to_csv('result/alerts/critical_file_alerts.csv', index=False)

        # 2. Top Risky Users Summary
        user_summary = sensitive_df.groupby('user').agg({
            'risk_score': ['count', 'sum', 'max'],
            'is_high_risk_action': 'sum'
        }).reset_index()
        user_summary.columns = ['user', 'event_count', 'total_risk_score', 'max_single_score', 'high_risk_actions_count']
        user_summary = user_summary.sort_values(by='total_risk_score', ascending=False)
        user_summary.to_csv('result/summaries/top_risky_users.csv', index=False)

        print(f"  - Organized file analysis reports generated in alerts/ and summaries/")
        
        # Return top N risky users for dynamic investigation
        return user_summary.head(3)['user'].tolist()
        
    except Exception as e:
        print(f"  - Error in File Analysis: {e}")
        return []

def generate_investigation_report(target_user):
    """Dynamic investigator for any given user."""
    print(f"  > Creating Investigation Timeline for: {target_user}...")
    try:
        # Load all source logs
        auth_df = pd.read_csv('RAW_DATA/auth_logs.csv')
        file_df = pd.read_csv('RAW_DATA/file_logs.csv')
        usb_df = pd.read_csv('RAW_DATA/usb_logs.csv')
        proc_df = pd.read_csv('RAW_DATA/endpoint_logs.csv')

        # Standardize and Filter
        auth = auth_df[auth_df['user'] == target_user].copy()
        auth['event_type'] = 'AUTHENTICATION'
        auth['detail'] = auth['action'] + " (" + auth['ip'] + ")"
        
        files = file_df[file_df['user'] == target_user].copy()
        files['event_type'] = 'FILE_ACCESS'
        files['detail'] = files['action'] + " " + files['filename']
        
        usb = usb_df[usb_df['user'] == target_user].copy()
        usb['event_type'] = 'USB_ACTIVITY'
        usb['detail'] = usb['action'] + " device: " + usb['device']
        
        procs = proc_df[proc_df['user'] == target_user].copy()
        procs['event_type'] = 'PROCESS_EXEC'
        procs['detail'] = procs['event'] + ": " + procs['detail']

        # Merge Timeline
        timeline = pd.concat([
            auth[['timestamp', 'event_type', 'detail']],
            files[['timestamp', 'event_type', 'detail']],
            usb[['timestamp', 'event_type', 'detail']],
            procs[['timestamp', 'event_type', 'detail']]
        ])

        if timeline.empty:
            print(f"    ! No data found for user: {target_user}")
            return False

        timeline['timestamp'] = pd.to_datetime(timeline['timestamp'])
        timeline = timeline.sort_values(by='timestamp')

        output_path = f'result/investigations/investigation_{target_user}.csv'
        timeline.to_csv(output_path, index=False)
        return True
    except Exception as e:
        print(f"    ! Error investigating {target_user}: {e}")
        return False

def run_all_analysis(manual_user=None):
    print("\n=== STARTING CYBER SECURITY LOG ANALYSIS ===")
    ensure_dirs()
    
    analyze_email_threats()
    analyze_brute_force()
    analyze_suspicious_processes()
    
    # Run file analysis and get top suspect users dynamically
    top_suspects = analyze_sensitive_file_access()
    
    print(f"\n=== INVESTIGATION PHASE ===")
    if manual_user:
        print(f"Targeting Manual Investigation: {manual_user}")
        generate_investigation_report(manual_user)
    else:
        print(f"Targeting Automatic Investigation (Top 3 Suspects): {', '.join(top_suspects)}")
        if top_suspects:
            for user in top_suspects:
                generate_investigation_report(user)
        else:
            print("No high-risk suspects found.")
        
    print("\n=== ANALYSIS COMPLETE ===")
    print("Check 'result/' subdirectories for categorized reports.\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Security Log Analyzer")
    parser.add_argument('-u', '--user', help="Specify a specific user to investigate", type=str)
    args = parser.parse_args()

    run_all_analysis(manual_user=args.user)

