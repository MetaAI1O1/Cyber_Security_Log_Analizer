import os
from normalize_logs import normalize_logs
from analyze_logs import run_all_analysis

def main():
    print("====================================================")
    print("   Cyber Security Log Analyzer - Integrated Runner")
    print("====================================================\n")

    # Step 1: Normalize logs
    print("Phase 1: Normalizing Logs...")
    normalize_logs()

    # Step 2: Run Security Analysis
    print("\nPhase 2: Running Security Threat Analysis...")
    run_all_analysis()

    # Final Summary
    print("====================================================")
    print("   Analysis Summary")
    print("====================================================")
    if os.path.exists('result'):
        results = os.listdir('result')
        print(f"Total report files generated: {len(results)}")
        for file in results:
            print(f" - result/{file}")
    else:
        print("[Error] result directory not found.")
    print("====================================================")

if __name__ == "__main__":
    main()
