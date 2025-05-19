import os
import re
import sys
import argparse
import requests
from tqdm import tqdm
from dotenv import load_dotenv
from config import SECRET_PATTERNS

# ASCII Art Logo
def show_logo():
    print(r"""
     ██████╗ ██╗  ██╗███████╗███████╗
    ██╔════╝ ██║  ██║██╔════╝██╔════╝
    ██║  ███╗███████║███████╗███████╗
    ██║   ██║██╔══██║╚════██║╚════██║
    ╚██████╔╝██║  ██║███████║███████║
     ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
    >> GIT SECRETS Scanner v1.0 <<
    >> Developed by MrDark0x7 <<
    """)

class GitHubSecretScanner:
    def __init__(self):
        self.github_token = os.getenv("GH_TOKEN")
        self.headers = {"Authorization": f"Bearer {self.github_token}"} if self.github_token else {}
        self.base_api_url = "https://api.github.com"

    def scan_repo(self, repo: str):
        findings = []
        url = f"{self.base_api_url}/repos/{repo}/contents"
        
        while url:
            try:
                response = requests.get(url, headers=self.headers)
                if response.status_code != 200:
                    print(f"\nError: Failed to fetch {url} (Status: {response.status_code})")
                    break
                
                for item in tqdm(response.json(), desc="Scanning files"):
                    if item["type"] == "dir":
                        subdir_findings = self.scan_repo(f"{repo}/{item['path']}")
                        findings.extend(subdir_findings)
                    elif item["type"] == "file":
                        try:
                            content = requests.get(item["download_url"]).text
                            file_findings = self.scan_content(content)
                            if file_findings:
                                findings.append({
                                    "file": item["path"],
                                    "findings": file_findings
                                })
                        except KeyError:
                            continue
            
                url = response.links.get("next", {}).get("url")
            except Exception as e:
                print(f"\nError during scanning: {str(e)}")
                break
        
        return findings

    def scan_local_path(self, path: str):
        findings = []
        if os.path.isfile(path):
            with open(path, "r") as f:
                content = f.read()
                if results := self.scan_content(content):
                    findings.extend([{"file": path, **r} for r in results])
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, "r") as f:
                            content = f.read()
                            if results := self.scan_content(content):
                                findings.extend([{"file": file_path, **r} for r in results])
                    except UnicodeDecodeError:
                        continue
        return findings

    def scan_content(self, content: str):
        results = []
        for line_num, line in enumerate(content.split("\n"), 1):
            for secret_type, pattern in SECRET_PATTERNS.items():
                if re.search(pattern, line):
                    results.append({
                        "type": secret_type,
                        "line": line_num,
                        "snippet": line.strip()[:50] + "..."
                    })
        return results

def main():
    load_dotenv()
    show_logo()
    
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--repo", help="GitHub repo (format: owner/repo)")
    parser.add_argument("--path", help="Local directory/file path to scan")
    
    args = parser.parse_args()
    scanner = GitHubSecretScanner()

    if not any(vars(args).values()):
        print("\n[1] Scan GitHub Repository")
        print("[2] Scan Local Directory/File")
        print("[3] Exit\n")
        choice = input("Choose an option: ")
        
        if choice == '1':
            args.repo = input("Enter GitHub repo (owner/repo): ")
        elif choice == '2':
            args.path = input("Enter local path: ")
        else:
            sys.exit()

    try:
        if args.repo:
            print(f"\nScanning GitHub repository: {args.repo}")
            findings = scanner.scan_repo(args.repo)
            print(f"\nFound {len(findings)} potential secrets:")
            for finding in findings:
                print(f"File: {finding['file']}")
                for secret in finding["findings"]:
                    print(f"  - Type: {secret['type']} (Line {secret['line']})")
                    print(f"    Snippet: {secret['snippet']}\n")
        
        elif args.path:
            print(f"\nScanning local path: {args.path}")
            findings = scanner.scan_local_path(args.path)
            print(f"\nFound {len(findings)} potential secrets:")
            for finding in findings:
                print(f"File: {finding['file']}")
                print(f"  - Type: {finding['type']} (Line {finding['line']})")
                print(f"    Snippet: {finding['snippet']}\n")
                
    except KeyboardInterrupt:
        print("\nScan aborted by user!")
        sys.exit(1)

if __name__ == "__main__":
    main()
