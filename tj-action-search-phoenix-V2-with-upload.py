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

def get_access_token(client_id, client_secret, base_url="https://api.demo.appsecphx.io"):
    """
    Obtains a time-limited access token from the Phoenix platform via Basic Auth.
    If client_id or client_secret are missing, the user is prompted once and stored.
    
    :param client_id: Phoenix API Client ID
    :param client_secret: Phoenix API Client Secret
    :param base_url: The base URL for Phoenix Security. For SaaS production,
                     use "https://api.securityphoenix.cloud". For demos,
                     "https://api.demo.appsecphx.io", or
                     "https://api.poc1.appsecphx.io" for enterprise PoC.
    :return: The Bearer token string, or None if authentication failed.
    """
    # Prompt if missing
    if not client_id:
        client_id = input("Enter your Phoenix Client ID (CLIENT_ID): ").strip()
        os.environ["CLIENT_ID"] = client_id
    if not client_secret:
        client_secret = input("Enter your Phoenix Client Secret (CLIENT_SECRET): ").strip()
        os.environ["CLIENT_SECRET"] = client_secret

    if not client_id or not client_secret:
        print("Error: Missing Phoenix client_id or client_secret.")
        return None

    # Access token endpoint
    url = f"{base_url}/v1/auth/access_token"
    print(f"Requesting Phoenix token from: {url}")

    response = requests.get(url, auth=HTTPBasicAuth(client_id, client_secret))
    if response.status_code == 200:
        payload = response.json()
        token = payload.get('token')
        expiry = payload.get('expiry')  # Unix timestamp
        print("Token obtained successfully.")
        print(f"Token expires at: {expiry} (Unix timestamp)")
        return token
    else:
        print(f"Failed to obtain token: HTTP {response.status_code}")
        print("Response:", response.text)
    return None

def send_results(
    file_path,
    scan_type,
    assessment_name,
    import_type,
    client_id,
    client_secret,
    base_url="https://api.demo.appsecphx.io",
    scan_target=None,
    auto_import=True
):
    """
    Uploads the Phoenix-format JSON directly to the /v1/import/assets endpoint,
    using a time-limited Bearer token for authentication.

    :param file_path: Path to the Phoenix-format JSON file
    :param scan_type: e.g. "Static Code Analysis", "SAST", etc.
    :param assessment_name: e.g. "TJ-Actions Vulnerability Assessment"
    :param import_type: "new", "merge", or "delta"
    :param client_id: Phoenix Client ID
    :param client_secret: Phoenix Client Secret
    :param base_url: Base URL for Phoenix Security API
    :param scan_target: (Optional) A target name or URL for your scanned environment
    :param auto_import: If true, automatically imports results; if false, they may be queued
    """
    # Obtain a Bearer token from Phoenix
    token = get_access_token(client_id, client_secret, base_url=base_url)
    if token is None:
        print("Could not retrieve token. Exiting upload.")
        return

    # Final import endpoint
    import_url = f"{base_url}/v1/import/assets"
    print(f"\nSending data to Phoenix: {import_url}")

    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

    # Read the JSON file content
    with open(file_path, 'r') as f:
        json_data = json.load(f)

    # Prepare the payload
    payload = {
        'scanType': scan_type,
        'assessmentName': assessment_name,
        'importType': import_type,
        'scanTarget': scan_target if scan_target else '',
        'autoImport': auto_import,
        'data': json_data
    }

    response = requests.post(import_url, headers=headers, json=payload)

    if response.status_code in [200, 201]:
        print("Data upload successful.")
    elif response.status_code == 401:
        print("401 Unauthorized. Token may have expired or credentials invalid.")
    else:
        print(f"Error uploading data: {response.status_code}")

    try:
        print("Response JSON:", response.json())
    except:
        print("Response text:", response.text)

##########################
# SCANNER CONFIG & LOGIC #
##########################

# Dynamically generate vulnerable patterns for every version from v1 to v45.0.7
VULNERABLE_PATTERNS = []

# Include the known malicious SHA
MALICIOUS_SHA = "uses: tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67"
VULNERABLE_PATTERNS.append(MALICIOUS_SHA)


# Generate patterns for versions v1.0.0 to v45.0.7
for major in range(1, 46):
    for minor in range(0, 8):  # Assuming minor versions go up to 7
        for patch in range(0, 8):  # Assuming patch versions go up to 7
            if major == 45 and minor == 0 and patch == 7:
                VULNERABLE_PATTERNS.append("uses: tj-actions/changed-files@v45.0.7")
            else:
                VULNERABLE_PATTERNS.append(f"uses: tj-actions/changed-files@v{major}.{minor}.{patch}")

# Remove duplicates if any
VULNERABLE_PATTERNS = list(set(VULNERABLE_PATTERNS))

def get_metadata_for_pattern(matched_pattern: str):
    """
    Returns a (severity, description) tuple based on the matched pattern.
    Includes a multi-line explanation with the specific version substituted.
    """
    version = matched_pattern.split('@')[-1].strip()
    advisory_text = f"""You are using version {version} which is currently compromised, it is dumping sensitive information, you should remove this immediately to prevent further compromise to your GitHub repositories.
It is recommended to:
1. Remove it from your actions immediately
2. Rotate your credentials where necessary
3. Investigate the secrets in your repositories to see if they were used maliciously
You should search your organization with this rule, but also https://github.com/search?q=org%3A%3CYOURORG%3E+uses%3A+tj-actions%2F&type=code and enter your organization which will help narrow down affected repositories.
Every version of tj-actions is compromised, all tags point to 0e58ed8 which is the compromised PR. Public repos should assume they are compromised.
It's currently unclear if credentials were also exfiltrated.
VULNERABLE CODE: uses: tj-actions/changed-files@5e85e31a0187e8df23b438284aa04f21b55f1510
https://github.com/chains-project/maven-lockfile/pull/1111	
https://github.com/espressif/arduino-esp32/issues/11127	
https://github.com/github/docs/blob/962a1c8dccb8c0f66548b324e5b921b5e4fbc3d6/content/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions.md?plain=1#L191-L193	
https://github.com/modal-labs/modal-examples/issues/1100	
https://github.com/rackerlabs/genestack/pull/903	
https://github.com/tj-actions/changed-files/blob/45fb12d7a8bedb4da42342e52fe054c6c2c3fd73/README.md?plain=1#L20-L28	
https://github.com/tj-actions/changed-files/issues/2463	
https://github.com/tj-actions/changed-files/issues/2464	
https://news.ycombinator.com/item?id=43367987	
https://news.ycombinator.com/item?id=43368870	
https://semgrep.dev/blog/2025/popular-github-action-tj-actionschanged-files-is-compromised/	
https://sysdig.com/blog/detecting-and-mitigating-the-tj-actions-changed-files-supply-chain-attack-cve-2025-30066/	
https://web.archive.org/web/20250315060250/https://github.com/tj-actions/changed-files/issues/2463	
https://www.stepsecurity.io/blog/harden-runner-detection-tj-actions-changed-files-action-is-compromised
"""

    if version in ["v45.0.7", "v1.1.3"]:
        severity = "8.6"
    elif version == "0e58ed8671d6b60d0890c21b07f8835ace038e67":
        severity = "9.8"
    else:
        severity = "1" #phoenix severity is 1 for information 

    description = f"vulnerable code line,\n{advisory_text}"
    return severity, description

def search_code_in_org(org_name="Security-Phoenix-demo"):
    """
    Search for lines referencing 'tj-actions/changed-files'.
    Prompts once for an organization name if it isn't set,
    then also prompts for GITHUB_TOKEN if missing.
    """
    import sys
    import os
    import requests

    # Prompt for org_name if somehow empty
    if not org_name:
        org_input = input("Enter your GitHub organization name (default: 'Security-Phoenix-demo'): ").strip()
        if org_input:
            org_name = org_input
        else:
            org_name = "Security-Phoenix-demo"

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

    print(f"Performing GitHub code search in organization: {org_name}")
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
    Converts the scanner's 'findings' into Phoenix's JSON structure.
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
    for item in items:
        repo_full = item['repository']['full_name']
        path = item['path']
        content = get_file_content(repo_full, path)
        if content:
            file_vulns = check_vulnerabilities_in_file(content)
            for (line_number, matched_pattern, line_text) in file_vulns:
                # Extract the vulnerable version
                version = matched_pattern.split('@')[-1].strip()

                # Build or retrieve your severity + multi-line advisory
                severity, advisory_text = get_metadata_for_pattern(matched_pattern)

                # Format location to include all requested info
                location_str = f"{repo_full}/{path} (line {line_number})"

                # Make sure the description has the version and line as requested
                # For example, we can add the line content or version:
                enhanced_description = (
                    f"Vulnerable reference to tj-actions/changed-files@{version}. "
                    f"Line {line_number} content:\n\n"
                    f"    {line_text}\n\n"
                    f"{advisory_text}"  # from get_metadata_for_pattern
                )

                # Also place the vital info in details for CSV/JSON
                details_str = (
                    f"Location: {location_str}\n"
                    f"Vulnerable version: {version}\n"
                    f"Line text:\n{line_text}\n\n"
                    f"Complete advisory:\n{advisory_text}"
                )

                findings.append({
                    "at_origin": "github",
                    "at_repository": repo_full,   # or "github/workflows" if you prefer
                    "at_build": path,
                    "at_dockerfile": "",
                    "at_scanner_source": f"github/workflows/{path}",
                    "a_tags": "",
                    "v_name": f"Vulnerability at line {line_number} for version {version}",
                    # Description shows the version and snippet:
                    "v_description": enhanced_description,
                    "v_remedy": "Remove/upgrade vulnerable reference and rotate credentials.",
                    "v_severity": severity,   # "1 = information", "7", or "9.8"
                    # v_location is now a string with repository, file path, and line:
                    "v_location": location_str,
                    "v_cve": "CVE-2025-30066",
                    "v_cwe": "CWE-506",
                    "v_tags": "",
                    "v_details": details_str
                })

    if not findings:
        print("No vulnerabilities found.")
        return

    # Print summary
    print("\nVulnerabilities found:")
    for f in findings:
        print(
            f"- {f['v_location']} => severity {f['v_severity']} => {f['v_description'][:60]}..."
        )

    # 1) Write CSV
    csv_file = "tj_action_vulns.csv"
    with open(csv_file, mode="w", newline="", encoding="utf-8") as f_out:
        writer = csv.DictWriter(
            f_out,
            fieldnames=[
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
                "v_tags",
                "v_details"
            ]
        )
        writer.writeheader()
        writer.writerows(findings)
    print(f"CSV output saved to: {csv_file}")

    # 2) Write JSON
    json_file = "tj_action_vulns.json"
    with open(json_file, mode="w", encoding="utf-8") as jf_out:
        json.dump(findings, jf_out, indent=4)
    print(f"JSON output saved to: {json_file}")

    # 3) Generate Phoenix-format JSON
    phoenix_data = generate_phoenix_format(findings)
    phoenix_json_file = "tj_action_vulns_phoenix.json"
    with open(phoenix_json_file, mode="w", encoding="utf-8") as pf_out:
        json.dump(phoenix_data, pf_out, indent=4)
    print(f"Phoenix-format JSON saved to: {phoenix_json_file}")

    # 4) Optionally upload to Phoenix
    #    Prompt once for client_id/client_secret if not in environment.
    client_id = os.environ.get("CLIENT_ID", "")
    client_secret = os.environ.get("CLIENT_SECRET", "")
    print("\nImporting Phoenix-format JSON into the platform...")

    # Adjust base_url as needed, e.g. for production: base_url="https://api.securityphoenix.cloud"
    send_results(
        file_path=phoenix_json_file,
        scan_type="Static Code Analysis",
        assessment_name="TJ-Actions Vulnerability Assessment",
        import_type="merge",  # or "new", "delta"
        client_id=client_id,
        client_secret=client_secret,
        base_url="https://api.demo.appsecphx.io",
        scan_target="GitHub org: Security-Phoenix-demo",
        auto_import=True
    )

if __name__ == "__main__":
    main()