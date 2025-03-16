#!/usr/bin/env python3
import os
import sys
import csv
import json
import requests
from requests.auth import HTTPBasicAuth

# Patterns considered vulnerable
VULNERABLE_PATTERNS = [
    "uses: tj-actions/changed-files@v35",
    "uses: tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67",
    "uses: tj-actions/changed-files@v1.1.3"
]

def get_metadata_for_pattern(matched_pattern: str):
    """
    Returns a (severity, description) tuple based on the matched pattern.
    Includes a multi-line explanation with the specific version substituted.
    """
    version = matched_pattern.split('@')[-1].strip()

    advisory_text = f"""You are using version {version} which is currently compromised, it is dumping sensitive
information, you should remove this immediately to prevent further
compromise to your GitHub repositories.

It is recommended to:

1. Remove it from your actions immediately
2. Rotate your credentials where necessary
3. Investigate the secrets in your repositories to see if they were used maliciously

You should search your organization with this rule, but also https://github.com/search?q=org%3A%3CYOURORG%3E+uses%3A+tj-actions%2F&type=code and enter your organization which will help narrow down affected repositories.
Every version of tj-actions is compromised, all tags point to 0e58ed8 which is the compromised PR. public repos should assume they are compromised.
It's currently unclear if the credentials were also exfiltrated to an arbitrary domain.

VULNERABLE CODE: uses: tj-actions/changed-files@5e85e31a0187e8df23b438284aa04f21b55f1510
"""

    # Decide severity based on pattern
    if version in ["v35", "v1.1.3"]:
        severity = "7"
    elif version == "0e58ed8671d6b60d0890c21b07f8835ace038e67":
        severity = "9.8"
    else:
        severity = "0"

    # Final description
    description = f"vulnerable code line,\n{advisory_text}"
    return severity, description

def search_code_in_org(org_name="Security-Phoenix-demo"):
    """
    Search for lines referencing 'tj-actions/changed-files'.
    Uses the GITHUB_TOKEN from environment; if missing, we exit.
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("Error: No GITHUB_TOKEN found in environment. Exiting.")
        sys.exit(1)

    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {github_token}"
    }

    query = f"org:{org_name} uses: tj-actions/changed-files"
    url = f"https://api.github.com/search/code?q={query}&per_page=100"

    print("Performing GitHub code search...")
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    search_results = response.json()

    items = search_results.get("items", [])
    print(f"Found {len(items)} file matches in search results.")
    return items

def get_file_content(repository_full_name, path):
    """
    Retrieve raw content of a file from GitHub.
    Uses the GITHUB_TOKEN from environment; if missing, we exit.
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        print("Error: No GITHUB_TOKEN found in environment. Exiting.")
        sys.exit(1)

    headers = {
        "Accept": "application/vnd.github.raw",
        "Authorization": f"Bearer {github_token}"
    }
    url = f"https://api.github.com/repos/{repository_full_name}/contents/{path}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Could not fetch file content for {repository_full_name}/{path} (status code {response.status_code}).")
        return None

def check_vulnerabilities_in_file(file_content):
    """
    Returns a list of (line_number, matched_pattern, line_text) for each match.
    """
    if not file_content:
        return []

    results = []
    lines = file_content.splitlines()
    for idx, line in enumerate(lines, start=1):
        for pattern in VULNERABLE_PATTERNS:
            if pattern in line:
                results.append((idx, pattern, line))
    return results

def main():
    # Prompt once for token, store in environment to avoid repeated prompts
    if not os.environ.get("GITHUB_TOKEN"):
        token_input = input("Enter your GitHub Personal Access Token (GITHUB_TOKEN): ").strip()
        if not token_input:
            print("Error: No token provided.")
            sys.exit(1)
        os.environ["GITHUB_TOKEN"] = token_input

    org_name = "Security-Phoenix-demo"
    print(f"Starting search for vulnerabilities in org: {org_name}")
    items = search_code_in_org(org_name)

    findings = []

    for item in items:
        repo_full = item['repository']['full_name']
        path = item['path']
        file_content = get_file_content(repo_full, path)
        if file_content:
            file_vulns = check_vulnerabilities_in_file(file_content)
            if file_vulns:
                for (line_number, matched_pattern, matched_line_text) in file_vulns:
                    severity, custom_description = get_metadata_for_pattern(matched_pattern)

                    # Print the file, line content, and the description with the requested spacing
                    print(f"File: {repo_full}/{path}")
                    print(f"Line: {line_number}")
                    print(f"Matched pattern: {matched_pattern}")
                    print(f"Line content: {matched_line_text}")
                    print("\n" * 5)  # 5 blank lines
                    print("=====")
                    print(custom_description)
                    print()  # extra newline

                    # Collect into findings
                    findings.append({
                        "a_id": "",
                        "at_origin": "github",
                        "at_repository": "github/workflows",
                        "at_build": path,
                        "at_dockerfile": "",
                        "at_scanner_source": f"github/workflows/{path}",
                        "a_tags": "",
                        "v_name": f"Detected Vulnerability (line {line_number})",
                        "v_description": custom_description,
                        "v_remedy": "Remove vulnerable references and rotate credentials (see description).",
                        "v_severity": severity,
                        "v_location": line_number,
                        "v_cve": "CVE-2025-30066",
                        "v_cwe": "CWE-74, CWE-77",
                        "v_published_datetime": "",
                        "v_tags": "",
                        "v_details": (
                            f"File: {repo_full}/{path}, line {line_number}\n"
                            f"Matched pattern: '{matched_pattern}'\n"
                            f"Line content: '{matched_line_text}'\n"
                            f"{custom_description}"
                        )
                    })

    if not findings:
        print("No vulnerabilities found.")
        return

    print("\nVulnerabilities found in total:", len(findings))

    # Example CSV output
    csv_file = "tj_action_vulns.csv"
    with open(csv_file, "w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(f_out, fieldnames=[
            "a_id",
            "at_origin",
            "at_repository",
            "at_build",
            "at_dockerfile",
            "at_scanner_source",
            "a_tags",
            "v_name",
            "v_description",
            "v_remedy",
            "v_severity",
            "v_location",
            "v_cve",
            "v_cwe",
            "v_published_datetime",
            "v_tags",
            "v_details"
        ])
        writer.writeheader()
        writer.writerows(findings)

    print(f"CSV output saved to: {csv_file}")

    # Example JSON output
    json_file = "tj_action_vulns.json"
    with open(json_file, "w", encoding="utf-8") as jf_out:
        json.dump(findings, jf_out, indent=4)
    print(f"JSON output saved to: {json_file}")

    # If needed, you can generate Phoenix-format JSON or call send_results() here.

if __name__ == "__main__":
    main()