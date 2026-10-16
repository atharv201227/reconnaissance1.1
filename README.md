# reconnaissance1.1

Interactive Python-based reconnaissance helper for **authorized bug bounty and security testing**. It prompts for a target domain and optional settings, then orchestrates installed command-line tools to collect subdomains, DNS results, HTTP services, archived URLs, and JavaScript URL candidates.

> **Authorization required:** Use only domains and assets you own or are explicitly authorized to assess. Confirm each discovered asset is in the relevant program's scope before further testing. Passive discovery, ASN lookups, cloud discovery, crawling, and fuzzing can all produce results outside scope. Follow program rules and rate limits.

## Features

- **Passive subdomain discovery:** Subfinder, Amass passive enumeration, and crt.sh.
- **Optional GitHub discovery:** Uses `github-subdomains` if installed and a token is supplied.
- **Optional DNS enumeration:** MassDNS, Shuffledns, and DNSX.
- **Optional HTTP probing:** HTTPX.
- **Optional hostname fuzzing:** FFUF, with a separate confirmation prompt.
- **Historical URL collection:** GAU and Waybackurls.
- **Optional crawling:** Katana and GoSpider, gated behind active-testing prompts.
- **Organized output:** Deduplicated subdomain lists, archived URLs, URLs containing query parameters, and JavaScript URL candidates.

The script skips tools that are not installed. It does not install dependencies or determine whether discovered assets are in scope.

## Requirements

- Python 3.9+ recommended.
- External tools installed and available on your `PATH`, as needed:
  - `subfinder`
  - `amass`
  - `jq` is not required by this Python script
  - `github-subdomains` (optional)
  - `massdns` (optional)
  - `shuffledns` (optional)
  - `dnsx` (optional)
  - `httpx` from ProjectDiscovery (optional)
  - `ffuf` (optional)
  - `gau` (optional)
  - `waybackurls` (optional)
  - `katana` (optional)
  - `gospider` (optional)
  - `cloud_enum` (optional)

Install tools using their official project documentation and check their individual licenses and usage instructions. Tool flags can differ between versions.

## Run

```bash
python3 reconnaissance1.1.py
```

If you keep the original filename, run:

```bash
python3 authorized_bug_bounty_enumerator.py
```

The script asks for:
1. Confirmation that you have authorization.
2. Root domain (for example, `example.com`).
3. Confirmation that the domain is explicitly in scope.
4. Output directory.
5. Optional subdomain wordlist and DNS resolver file paths.
6. Optional GitHub token and verified ASN.
7. Whether to enable active DNS/HTTP probing, FFUF, crawling, and cloud/ASN discovery.

Leave optional values blank to skip those integrations.

## Output files

Output is written to the selected directory. Depending on enabled options and installed tools, files may include:

| File | Purpose |
|---|---|
| `README.txt` | Scope reminder and run metadata |
| `subfinder_subs.txt` | Subfinder output |
| `amass_passive_subs.txt` | Amass passive results |
| `crtsh_subs.txt` | crt.sh certificate-transparency names |
| `github_subs.txt` | Optional GitHub discovery results |
| `all_subs.txt` | Merged and domain-filtered passive subdomains |
| `asn_results.txt` | Optional ASN intelligence results |
| `massdns_results.txt` | Optional MassDNS output |
| `active_subs.txt` | Input list used for active resolution/probing |
| `dnsx_results.txt` | Optional DNSX results |
| `live_websites.txt` | HTTPX results, or seed URLs if active probing is disabled |
| `ffuf_subs.json` | Optional FFUF results |
| `gau_urls.txt` | Archived URLs from GAU |
| `wayback_urls.txt` | URLs from Waybackurls |
| `katana_urls.txt` | Optional Katana crawl output |
| `all_archived_urls.txt` | Merged URL results |
| `parameter_urls.txt` | URLs containing `=` |
| `javascript_urls.txt` | URLs that appear to reference JavaScript files |

Not every file is created on every run. Tool errors, missing dependencies, network issues, and version differences may affect results.

## Security and privacy notes

- Treat discovered credentials, tokens, and personal data as sensitive. Do not commit secrets, raw tokens, or private target data to a public repository.
- The script intentionally does not write the GitHub token into its output files; it passes the token through an environment variable for the optional GitHub command.
- Use a least-privilege GitHub token and revoke it if it is exposed.
- Do not use or test third-party credentials discovered during reconnaissance.
- Review every result manually. A discovered hostname or cloud resource is not automatically in scope.
- Active probing, crawling, and fuzzing can generate traffic. Keep rates and depth within the program's rules.
- This tool is a helper, not a vulnerability scanner, and it does not guarantee complete or accurate enumeration.

## Troubleshooting

- **Tool skipped:** Install the relevant tool and ensure its executable is on `PATH`.
- **Command-line option rejected:** Check the installed version's `-h` or `--help` output; update the command for that version.
- **No results:** The data source may have no results, be rate-limited, or be unavailable.
- **DNS tools do not run:** Provide valid paths to a wordlist and resolver file where requested.
- **Unexpected assets:** Manually confirm ownership and program scope before testing.

## Disclaimer

This project is intended for authorized security research, asset inventory, and bug bounty reconnaissance. You are responsible for obtaining permission, following applicable laws, and complying with each target's rules of engagement.

## License

No license has been specified yet. Add a `LICENSE` file before encouraging reuse or redistribution.
