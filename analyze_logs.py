import pandas as pd
import os

# Create result directory if not exists
if not os.path.exists('result'):
    os.makedirs('result')

def analyze_email_threats():
    print("Analyzing Email Threats...")
    try:
        df = pd.read_csv('RAW_DATA/email_logs.csv')
        malicious_exts = ['.exe', '.scr', '.bat', '.js', '.vbs', '.ps1', '.zip']
        keywords = ['urgent', 'invoice', 'malicious', 'password', 'login', 'account']
        
        # Check for malicious extensions
        suspicious_attachments = df[df['attachment'].str.endswith(tuple(malicious_exts), na=False)]
        
        # Check for suspicious keywords in subject
        suspicious_subjects = df[df['subject'].str.contains('|'.join(keywords), case=False, na=False)]
        
        result = pd.concat([suspicious_attachments, suspicious_subjects]).drop_duplicates()
        result.to_csv('result/email_threats.csv', index=False)
        print(f"  - Found {len(result)} suspicious emails.")
    except Exception as e:
        print(f"  - Error: {e}")

def analyze_brute_force():
    print("Analyzing Login Failures & Brute Force...")
    try:
        df = pd.read_csv('RAW_DATA/auth_logs.csv')
        failed_logins = df[df['action'] == 'failed_login']
        
        # Count failures per IP and user
        brute_force_stats = failed_logins.groupby(['ip', 'user']).size().reset_index(name='failure_count')
        brute_force_stats = brute_force_stats.sort_values(by='failure_count', ascending=False)
        
        brute_force_stats.to_csv('result/brute_force_analysis.csv', index=False)
        print(f"  - Found {len(brute_force_stats)} potential brute force sources.")
    except Exception as e:
        print(f"  - Error: {e}")

def analyze_suspicious_processes():
    print("Analyzing Suspicious Process Execution...")
    try:
        df = pd.read_csv('RAW_DATA/endpoint_logs.csv')
        
        # PowerShell or CMD usage
        suspicious = df[
            (df['event'] == 'powershell') | 
            (df['detail'].str.contains('cmd.exe|powershell.exe|bash.exe|sh.exe', case=False, na=False))
        ]
        
        suspicious.to_csv('result/suspicious_processes.csv', index=False)
        print(f"  - Found {len(suspicious)} suspicious process activities.")
    except Exception as e:
        print(f"  - Error: {e}")

def analyze_dns_beaconing():
    print("Analyzing DNS Beaconing...")
    try:
        df = pd.read_csv('RAW_DATA/dns_logs.csv')
        
        # Frequency of queries per host and domain
        beaconing = df.groupby(['host', 'query']).size().reset_index(name='query_count')
        beaconing = beaconing.sort_values(by='query_count', ascending=False)
        
        # Filter high frequency (arbitrary threshold > 10 for demonstration)
        high_freq = beaconing[beaconing['query_count'] > 10]
        
        high_freq.to_csv('result/dns_beaconing_analysis.csv', index=False)
        print(f"  - Found {len(high_freq)} frequent DNS query patterns.")
    except Exception as e:
        print(f"  - Error: {e}")

def analyze_outbound_traffic():
    print("Analyzing Suspicious Outbound Traffic...")
    try:
        # Netflow analysis for high volume
        df_netflow = pd.read_csv('RAW_DATA/netflow_logs.csv')
        
        # Simple heuristic: filter for external IPs (not starting with 10.)
        external_traffic = df_netflow[~df_netflow['dst_ip'].str.startswith('10.', na=False)]
        
        # Data exfiltration per host
        exfiltration = external_traffic.groupby('src_ip')['bytes'].sum().reset_index(name='total_bytes_out')
        exfiltration = exfiltration.sort_values(by='total_bytes_out', ascending=False)
        
        exfiltration.to_csv('result/data_exfiltration_summary.csv', index=False)
        
        # High volume connections
        high_volume = external_traffic.sort_values(by='bytes', ascending=False).head(100)
        high_volume.to_csv('result/high_volume_outbound.csv', index=False)
        
        print(f"  - Analyzed {len(exfiltration)} hosts for data exfiltration.")
    except Exception as e:
        print(f"  - Error: {e}")

def analyze_sensitive_file_access():
    print("Analyzing Sensitive File Access...")
    try:
        df = pd.read_csv('RAW_DATA/file_logs.csv')
        
        # Filter high/medium sensitivity or sensitive extensions
        sensitive_files = df[
            (df['sensitivity'].isin(['high', 'medium'])) |
            (df['filename'].str.endswith(('.db', '.tar', '.zip', '.sql'), na=False))
        ]
        
        sensitive_files.to_csv('result/sensitive_file_access.csv', index=False)
        print(f"  - Found {len(sensitive_files)} sensitive file access records.")
    except Exception as e:
        print(f"  - Error: {e}")

def analyze_process_behavior():
    print("Analyzing Process Behavior Mapping...")
    try:
        df = pd.read_csv('RAW_DATA/endpoint_logs.csv')
        
        # Simple masquerading check: system processes run by regular users
        # and unusual parent-child relationships inferred from detail
        system_procs = ['lsass.exe', 'svchost.exe', 'services.exe', 'wininit.exe', 'smss.exe']
        
        # Flag if these processes appear in detail (assumed as child) 
        # but the event isn't system-initiated (this is a heuristic)
        masquerading = df[df['detail'].str.lower().isin(system_procs)]
        
        # Also check for common LOLBins that might be misused
        lolbins = ['certutil.exe', 'bitsadmin.exe', 'regsvr32.exe', 'mshta.exe', 'wmic.exe']
        suspicious_lolbins = df[df['detail'].str.lower().isin(lolbins)]
        
        mapping_result = pd.concat([masquerading, suspicious_lolbins]).drop_duplicates()
        mapping_result.to_csv('result/process_behavior_mapping.csv', index=False)
        print(f"  - Found {len(mapping_result)} potential process behavior anomalies.")
    except Exception as e:
        print(f"  - Error: {e}")

def run_all_analysis():
    print("\n=== Starting Security Threat Analysis ===")
    analyze_email_threats()
    analyze_brute_force()
    analyze_suspicious_processes()
    analyze_process_behavior()
    analyze_dns_beaconing()
    analyze_outbound_traffic()
    analyze_sensitive_file_access()
    print("=== Analysis Phase Complete ===\n")

if __name__ == "__main__":
    run_all_analysis()
    print("\nAnalysis complete. Results stored in 'result/' folder.")
