import pandas as pd
import os
import argparse
import ipaddress

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

def is_internal_ip(ip):
    """Return True for RFC1918/internal IPv4 addresses."""
    try:
        return ipaddress.ip_address(str(ip)).is_private
    except ValueError:
        return False

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

def analyze_process_masquerading():
    print("Analyzing Process Behavior Mapping (Masquerading)...")
    try:
        df = pd.read_csv('RAW_DATA/endpoint_logs.csv')
        df['event'] = df['event'].astype(str).str.lower()
        df['detail'] = df['detail'].astype(str)
        df['first_token'] = df['detail'].str.strip().str.split().str[0].str.lower()

        power_expected = df['first_token'].str.startswith(('powershell', 'pwsh'), na=False)
        cmd_expected = df['first_token'].str.startswith('cmd', na=False)

        power_mismatch = (df['event'] == 'powershell') & (~power_expected)
        cmd_mismatch = (df['event'] == 'cmd') & (~cmd_expected)

        masquerade = df[power_mismatch | cmd_mismatch].copy()
        masquerade['expected_behavior'] = masquerade['event'].map({
            'powershell': 'powershell* or pwsh*',
            'cmd': 'cmd*'
        })

        masquerade.to_csv('result/raw_analysis/process_masquerading_analysis.csv', index=False)
        masquerade[['timestamp', 'host', 'user', 'event', 'detail', 'expected_behavior']].to_csv(
            'result/alerts/process_masquerading_alerts.csv',
            index=False
        )

        print("  - Results saved to result/alerts/process_masquerading_alerts.csv")
    except Exception as e:
        print(f"  - Error in Process Masquerading Analysis: {e}")

def analyze_dns_beaconing():
    print("Analyzing DNS Query Frequency (Beaconing)...")
    try:
        df = pd.read_csv('RAW_DATA/dns_logs.csv')
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        def summarize_group(group):
            times = group['timestamp'].sort_values()
            intervals = times.diff().dt.total_seconds().dropna()
            return pd.Series({
                'query_count': len(group),
                'first_seen': times.min(),
                'last_seen': times.max(),
                'unique_response_ips': group['response_ip'].nunique(),
                'avg_interval_sec': intervals.mean() if not intervals.empty else None,
                'interval_std_sec': intervals.std() if not intervals.empty else None
            })

        summary = df.groupby(['host', 'query'], as_index=False).apply(summarize_group)
        summary = summary.sort_values(by='query_count', ascending=False)
        summary.to_csv('result/summaries/dns_query_frequency_summary.csv', index=False)

        beacons = summary[
            (summary['query_count'] >= 60) &
            (summary['avg_interval_sec'].notna()) &
            (summary['avg_interval_sec'] <= 3600) &
            ((summary['interval_std_sec'].fillna(0)) <= 1800)
        ].copy()
        beacons.to_csv('result/alerts/dns_beaconing_alerts.csv', index=False)

        print("  - Results saved to result/alerts/dns_beaconing_alerts.csv")
    except Exception as e:
        print(f"  - Error in DNS Analysis: {e}")

def analyze_outbound_traffic():
    print("Analyzing Suspicious Outbound Traffic...")
    try:
        fw_df = pd.read_csv('RAW_DATA/firewall_logs.csv')
        nf_df = pd.read_csv('RAW_DATA/netflow_logs.csv')

        fw_df['dst_is_internal'] = fw_df['dst_ip'].apply(is_internal_ip)
        fw_external = fw_df[
            (fw_df['action'].astype(str).str.upper() == 'ALLOW') &
            (~fw_df['dst_is_internal'])
        ].copy()
        fw_external.to_csv('result/raw_analysis/firewall_external_connections.csv', index=False)

        fw_group = fw_external.groupby(['src_ip', 'dst_ip', 'port']).size().reset_index(name='connection_count')
        fw_count_threshold = fw_group['connection_count'].quantile(0.99) if not fw_group.empty else 0
        fw_hot = fw_group[fw_group['connection_count'] >= fw_count_threshold].copy()
        fw_hot['source'] = 'firewall'
        fw_hot = fw_hot.rename(columns={'connection_count': 'indicator_value'})

        nf_df['dst_is_internal'] = nf_df['dst_ip'].apply(is_internal_ip)
        nf_external = nf_df[~nf_df['dst_is_internal']].copy()
        nf_bytes_threshold = nf_external['bytes'].quantile(0.99) if not nf_external.empty else 0
        nf_hot = nf_external[nf_external['bytes'] >= nf_bytes_threshold].copy()
        nf_hot['source'] = 'netflow'
        nf_hot = nf_hot.rename(columns={'bytes': 'indicator_value'})
        nf_hot = nf_hot[['source', 'timestamp', 'src_ip', 'dst_ip', 'port', 'indicator_value']]

        fw_hot_out = fw_hot[['source', 'src_ip', 'dst_ip', 'port', 'indicator_value']].copy()
        fw_hot_out['timestamp'] = None
        fw_hot_out = fw_hot_out[['source', 'timestamp', 'src_ip', 'dst_ip', 'port', 'indicator_value']]

        outbound_alerts = pd.concat([fw_hot_out, nf_hot], ignore_index=True)
        outbound_alerts = outbound_alerts.sort_values(by='indicator_value', ascending=False)
        outbound_alerts.to_csv('result/alerts/suspicious_outbound_traffic.csv', index=False)

        outbound_summary = nf_external.groupby('src_ip', as_index=False).agg(
            outbound_event_count=('bytes', 'count'),
            total_outbound_bytes=('bytes', 'sum'),
            avg_outbound_bytes=('bytes', 'mean'),
            unique_external_destinations=('dst_ip', 'nunique')
        ).sort_values(by='total_outbound_bytes', ascending=False)
        outbound_summary.to_csv('result/summaries/outbound_traffic_summary.csv', index=False)

        print("  - Results saved to result/alerts/suspicious_outbound_traffic.csv")
    except Exception as e:
        print(f"  - Error in Outbound Traffic Analysis: {e}")

def quantify_data_exfiltration():
    print("Quantifying Data Exfiltration...")
    try:
        df = pd.read_csv('RAW_DATA/netflow_logs.csv')
        external_df = df[~df['dst_ip'].apply(is_internal_ip)].copy()

        host_exfil = external_df.groupby('src_ip', as_index=False).agg(
            outbound_connections=('bytes', 'count'),
            total_outbound_bytes=('bytes', 'sum'),
            max_single_transfer=('bytes', 'max'),
            unique_external_dst=('dst_ip', 'nunique')
        ).sort_values(by='total_outbound_bytes', ascending=False)

        host_exfil.to_csv('result/summaries/data_exfiltration_by_host.csv', index=False)

        threshold = host_exfil['total_outbound_bytes'].quantile(0.95) if not host_exfil.empty else 0
        exfil_alerts = host_exfil[host_exfil['total_outbound_bytes'] >= threshold].copy()
        exfil_alerts.to_csv('result/alerts/data_exfiltration_alerts.csv', index=False)

        print("  - Results saved to result/summaries/data_exfiltration_by_host.csv")
    except Exception as e:
        print(f"  - Error in Exfiltration Quantification: {e}")

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
    analyze_process_masquerading()
    analyze_dns_beaconing()
    analyze_outbound_traffic()
    quantify_data_exfiltration()
    
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

