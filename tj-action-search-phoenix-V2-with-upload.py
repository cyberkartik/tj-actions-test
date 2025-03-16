#!/usr/bin/env python3
import os
import sys
import csv
import json
import requests
from requests.auth import HTTPBasicAuth

############################
# PHOENIX HELPER FUNCTIONS #
############################

def get_access_token(client_id, client_secret):
    """
    Obtains an access token from the Phoenix platform.
    If client_id or client_secret are missing, the user is prompted once.
    """
    if not client_id:
        client_id = input("Enter your Phoenix Client ID (CLIENT_ID): ").strip()
        os.environ["CLIENT_ID"] = client_id
    if not client_secret:
        client_secret = input("Enter your Phoenix Client Secret (CLIENT_SECRET): ").strip()
        os.environ["CLIENT_SECRET"] = client_secret

    if not client_id or not client_secret:
        print("Error: Missing Phoenix client_id or client_secret.")
        return None

    # You can switch this endpoint to your environment as needed:
    # e.g. "https://api.demo.appsecphx.io/v1/auth/access_token"
    url = "https://api.poc1.appsecphx.io/v1/auth/access_token"

    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        return response.json()['token']
    else:
        print(f"Failed to obtain token: {response.status_code}")
        print("Response:", response.text)
    return None

def send_results(file_path, scan_type, assessment_name, import_type, client_id, client_secret,
                 scan_target=None, auto_import=True):
    """
    Uploads JSON or other file to the Phoenix file/translate API endpoint.
    If no client_id/secret in environment, prompt once for them and store so we don’t ask again.
    """
    token = get_access_token(client_id, client_secret)
    if token is None:
        return

    # Example endpoint. Use "https://api.demo.appsecphx.io/v1/import/assets/file/translate" for demo
    url = "https://api.poc1.appsecphx.io/v1/import/assets/file/translate"

    headers = {
        'Authorization': f'Bearer {token}'
    }
    files = {
        'file': (file_path, open(file_path, 'rb'), 'application/octet-stream')
    }
    data = {
        'scanType': scan_type,
        'assessmentName': assessment_name,
        'importType': import_type,
        'scanTarget': scan_target if scan_target else '',
        'autoImport': 'true' if auto_import else 'false'
    }

    response = requests.post(url, headers=headers, files=files, data=data)
    files['file'][1].close()
    print("Status Code:", response.status_code)
    try:
        print("Response:", response.json())
    except:
        print("Raw Response:", response.text)


##########################
# SCANNER CONFIG & LOGIC #
##########################

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
Every version of tj-actions is compromised, all tags point to 0e58ed8 which is the compromised PR. Public repos should assume they are compromised.
It's currently unclear if credentials were also exfiltrated.

VULNERABLE CODE: uses: tj-actions/changed-files@5e85e31a0187e8df23b438284aa04f21b55f1510
"""

    if version in ["v35", "v1.1.3"]:
        severity = "7"
    elif version == "0e58ed8671d6b60d0890c21b07f8835ace038e67":
        severity = "9.8"
    else:
        severity = "0"

    description = f"vulnerable code line,\n{advisory_text}"
    return severity, description

def search_code_in_org(org_name="Security-Phoenix-demo"):
    """
    Search for lines referencing 'tj-actions/changed-files'.
    If GITHUB_TOKEN is not in environment, prompt once and store it.
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        token_input = input("Enter your GitHub Personal Access Token (GITHUB_TOKEN): ").strip()
        if not token_input:
            print("Error: No token provided.")
            sys.exit(1)
        os.environ["GITHUB_TOKEN"] = token_input
        github_token = token_input

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
    Retrieve raw content of a file from GitHub using GITHUB_TOKEN.
    """
    github_token = os.environ.get("GITHUB_TOKEN")
    if not github_token:
        token_input = input("Enter your GitHub Personal Access Token (GITHUB_TOKEN): ").strip()
        if not token_input:
            print("Error: No token provided.")
            sys.exit(1)
        os.environ["GITHUB_TOKEN"] = token_input
        github_token = token_input

    headers = {
        "Accept": "application/vnd.github.raw",
        "Authorization": f"Bearer {github_token}"
    }
    url = f"https://api.github.com/repos/{repository_full_name}/contents/{path}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        print(f"Could not fetch file content for {repository_full_name}/{path}, status: {response.status_code}")
        return None

def check_vulnerabilities_in_file(file_content):
    """
    Returns a list of (line_number, matched_pattern, line_text) for each pattern found.
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


#################################
# GENERATE PHOENIX-FORMAT JSON  #
#################################

def generate_phoenix_format(findings):
    """
    Converts the scanner's 'findings' into Phoenix's JSON structure:
    {
        "importType": "merge",
        "assessment": {
            "assetType": "BUILD",
            "name": "TJ-Actions Vulnerability Assessment"
        },
        "assets": [
            {
              "id": "",
              "attributes": {
                  "repository": "...",
                  "buildFile": "...",
                  "dockerfile": "...",
                  "scannerSource": "...",
                  "origin": "..."
              },
              "tags": [],
              "installedSoftware": [],
              "findings": [...]
            }
        ]
    }
    """
    grouped_assets = {}
    for f in findings:
        key = (f["at_repository"], f["at_build"], f["at_scanner_source"])
        if key not in grouped_assets:
            grouped_assets[key] = {
                "id": "",
                "attributes": {
                    "repository": f["at_repository"],
                    "buildFile": f["at_build"],
                    "dockerfile": f["at_dockerfile"],
                    "scannerSource": f["at_scanner_source"],
                    "origin": f["at_origin"]
                },
                "tags": [],
                "installedSoftware": [],
                "findings": []
            }

        single_finding = {
            "name": f["v_name"],
            "description": f["v_description"],
            "remedy": f["v_remedy"],
            "severity": f["v_severity"],
            "location": str(f["v_location"]),
            "referenceIds": [f["v_cve"]] if f["v_cve"] else [],
            "cwes": [f["v_cwe"]] if f["v_cwe"] else [],
            "publishedDateTime": f["v_published_datetime"] or "",
            "details": {
                "rawDetails": f["v_details"] or ""
            }
        }
        grouped_assets[key]["findings"].append(single_finding)

    phoenix_data = {
        "importType": "merge",
        "assessment": {
            "assetType": "BUILD",
            "name": "TJ-Actions Vulnerability Assessment"
        },
        "assets": list(grouped_assets.values())
    }
    return phoenix_data


def main():
    org_name = "Security-Phoenix-demo"
    print(f"Starting search for vulnerabilities in org: {org_name}")
    items = search_code_in_org(org_name)

    findings = []

    # Gathering vulnerabilities
    for item in items:
        repo_full = item['repository']['full_name']
        path = item['path']
        content = get_file_content(repo_full, path)
        if content:
            file_vulns = check_vulnerabilities_in_file(content)
            for (line_number, matched_pattern, line_text) in file_vulns:
                severity, custom_description = get_metadata_for_pattern(matched_pattern)

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
                        f"Line content: '{line_text}'\n\n"
                        f"{custom_description}"
                    )
                })

    if not findings:
        print("No vulnerabilities found.")
        return

    # Print vulnerabilities summary to console
    print("\nVulnerabilities found:")
    for f in findings:
        print(
            f"- {f['at_build']}: line {f['v_location']} => severity {f['v_severity']} => {f['v_description'][:60]}..."
        )

    # 1) Write CSV output
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
    print(f"\nCSV output saved to: {csv_file}")

    # 2) Write JSON output
    json_file = "tj_action_vulns.json"
    with open(json_file, "w", encoding="utf-8") as jf_out:
        json.dump(findings, jf_out, indent=4)
    print(f"JSON output saved to: {json_file}")

    # 3) Generate Phoenix-format and store in file
    phoenix_data = generate_phoenix_format(findings)
    phoenix_json_file = "tj_action_vulns_phoenix.json"
    with open(phoenix_json_file, "w", encoding="utf-8") as pf_out:
        json.dump(phoenix_data, pf_out, indent=4)
    print(f"Phoenix-format JSON saved to: {phoenix_json_file}")

    # 4) Import results into Phoenix automatically
    #    Prompt once for client_id/client_secret if not in environment,
    #    then call the send_results function above.
    client_id = os.environ.get("CLIENT_ID", "")
    client_secret = os.environ.get("CLIENT_SECRET", "")
    print("\nImporting Phoenix-format JSON into the platform...")
    send_results(
        file_path=phoenix_json_file,
        scan_type="Static Code Analysis",
        assessment_name="TJ-Actions Vulnerability Assessment",
        import_type="merge",  # or "new", "delta"
        client_id=client_id,
        client_secret=client_secret,
        scan_target="GitHub org: Security-Phoenix-demo",
        auto_import=True
    )


if __name__ == "__main__":
    main()