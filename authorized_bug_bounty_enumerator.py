#!/usr/bin/env python3
"""
Authorized Bug Bounty Enumeration Helper
----------------------------------------
Interactive orchestrator for common passive/low-impact recon tools.

Use only on domains and assets you own or are explicitly authorized to test.
This script does not install tools, validate bounty scope, or guarantee that
third-party discovered assets are in scope.
"""

import os
import re
import sys
import shutil
import subprocess
import urllib.parse
import urllib.request
import json
from pathlib import Path
from datetime import datetime

BANNER = r"""
=========================================================
     AUTHORIZED BUG BOUNTY ENUMERATION HELPER
=========================================================
Passive discovery first. Active steps are opt-in.
"""

def ask(prompt, default=""):
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or default

def yes(prompt, default=False):
    hint = "Y/n" if default else "y/N"
    value = input(f"{prompt} ({hint}): ").strip().lower()
    if not value:
        return default
    return value in ("y", "yes")

def valid_domain(domain):
    domain = domain.strip().lower().rstrip(".")
    if len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    return all(
        len(label) <= 63
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label)
        for label in labels
    )

def safe_name(value):
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)

def write_lines(path, lines):
    path.parent.mkdir(parents=True, exist_ok=True)
    clean = sorted({str(x).strip() for x in lines if str(x).strip()})
    path.write_text("".join(x + "\n" for x in clean), encoding="utf-8")
    return len(clean)

def read_lines(path):
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(errors="ignore").splitlines() if line.strip()]

def tool_exists(name):
    return shutil.which(name) is not None

def _run_subprocess(args, stdin_handle, output_file=None, timeout=None):
    if output_file:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with output_file.open("w", encoding="utf-8") as out:
            return subprocess.run(
                args, stdin=stdin_handle, stdout=out,
                stderr=subprocess.PIPE, text=True, timeout=timeout, check=False
            )
    return subprocess.run(
        args, stdin=stdin_handle, text=True, timeout=timeout, check=False
    )

def run_command(label, args, output_file=None, stdin_file=None, timeout=None):
    print(f"\n[+] {label}")
    print("    " + " ".join(str(x) for x in args))
    if not tool_exists(args[0]):
        print(f"[!] Skipped: '{args[0]}' is not installed or not on PATH.")
        return False
    try:
        if stdin_file:
            with open(stdin_file, "rb") as stdin_handle:
                result = _run_subprocess(args, stdin_handle, output_file, timeout)
        else:
            result = _run_subprocess(args, subprocess.DEVNULL, output_file, timeout)
        if result.returncode != 0:
            print(f"[!] Command exited with status {result.returncode}.")
            if getattr(result, "stderr", ""):
                print(result.stderr[-1200:])
            return False
        print("[✓] Finished.")
        return True
    except subprocess.TimeoutExpired:
        print("[!] Timed out.")
    except OSError as exc:
        print(f"[!] Could not run command: {exc}")
    return False

def run_pipe_to_file(label, args, output_file, timeout=None):
    print(f"\n[+] {label}")
    print("    " + " ".join(str(x) for x in args))
    if not tool_exists(args[0]):
        print(f"[!] Skipped: '{args[0]}' is not installed or not on PATH.")
        return False
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
        if result.returncode != 0:
            print(f"[!] Command exited with status {result.returncode}.")
            if result.stderr:
                print(result.stderr[-1200:])
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(result.stdout or "", encoding="utf-8")
        print(f"[✓] Saved output to {output_file}")
        return result.returncode == 0
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"[!] Could not complete: {exc}")
        return False

def crtsh_lookup(domain, output_file):
    print("\n[+] Certificate Transparency lookup (crt.sh)")
    url = "https://crt.sh/?" + urllib.parse.urlencode({"q": f"%.{domain}", "output": "json"})
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "AuthorizedReconHelper/1.0"})
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
        names = []
        for row in data:
            name = str(row.get("name_value", ""))
            for item in name.splitlines():
                item = item.strip().lower().rstrip(".")
                if item.startswith("*."):
                    item = item[2:]
                # Keep only the requested domain and its subdomains.
                if item == domain or item.endswith("." + domain):
                    names.append(item)
        count = write_lines(output_file, names)
        print(f"[✓] Saved {count} unique names to {output_file}")
        return True
    except Exception as exc:
        print(f"[!] crt.sh lookup failed: {exc}")
        return False

def merge_files(paths, output):
    lines = []
    for path in paths:
        lines.extend(read_lines(path))
    count = write_lines(output, lines)
    print(f"\n[✓] Merged {count} unique entries into {output}")
    return count

def normalize_subdomains(path, domain):
    valid = []
    for item in read_lines(path):
        item = item.strip().lower().rstrip(".")
        if item.startswith("*."):
            item = item[2:]
        if item == domain or item.endswith("." + domain):
            valid.append(item)
    write_lines(path, valid)

def main():
    print(BANNER)
    print("Run this only against targets covered by your written authorization.")
    if not yes("Do you confirm that you are authorized to enumerate the target?", False):
        print("Exiting. Obtain authorization and confirm program scope first.")
        return 1

    domain = ask("Root domain to enumerate (example.com)").lower().strip().rstrip(".")
    if not valid_domain(domain):
        print("[!] That does not look like a valid root domain.")
        return 1

    print("\nConfirm the exact root domain is in scope. This script cannot determine bounty scope.")
    if not yes(f"Is {domain} explicitly in scope?", False):
        print("Exiting until scope is confirmed.")
        return 1

    base = Path(ask("Output directory", f"recon_{safe_name(domain)}_{datetime.now():%Y%m%d_%H%M%S}")).expanduser()
    base.mkdir(parents=True, exist_ok=True)
    print(f"\nOutputs will be saved under: {base.resolve()}")

    wordlist = ask("Subdomain wordlist path (optional; Enter to skip)", "")
    resolvers = ask("DNS resolvers file path (optional; Enter to skip)", "")
    github_token = ask("GitHub token (optional; leave blank to skip token-based search)", "")
    asn = ask("Verified in-scope ASN (optional, e.g. AS64500; Enter to skip)", "").upper()
    do_active = yes("Enable active DNS/brute-force/HTTP probing? Only if program rules allow it", False)
    do_fuzz = yes("Enable hostname fuzzing with FFUF? This sends active requests", False) if do_active else False
    do_cloud_asn = yes("Run ASN/cloud discovery? These can reveal assets outside program scope", False)
    do_crawl = yes("Collect archived URLs and crawl known live URLs?", True)
    do_js = yes("Collect JavaScript URLs for later manual review?", True)

    # Save settings without writing secrets.
    (base / "README.txt").write_text(
        "Authorized Bug Bounty Enumeration Helper output\n"
        f"Root domain: {domain}\n"
        "Confirm every discovered host is in the program's scope before testing it.\n"
        "GitHub token is intentionally not written to disk by this script.\n",
        encoding="utf-8"
    )

    passive_files = []
    subfinder_out = base / "subfinder_subs.txt"
    amass_out = base / "amass_passive_subs.txt"
    crtsh_out = base / "crtsh_subs.txt"
    github_out = base / "github_subs.txt"

    run_command("Subfinder passive/source enumeration",
                ["subfinder", "-d", domain, "-silent", "-all", "-o", str(subfinder_out)])
    passive_files.append(subfinder_out)

    run_command("Amass passive enumeration",
                ["amass", "enum", "-passive", "-d", domain, "-o", str(amass_out)])
    passive_files.append(amass_out)

    crtsh_lookup(domain, crtsh_out)
    passive_files.append(crtsh_out)

    if github_token:
        if tool_exists("github-subdomains"):
            env = os.environ.copy()
            env["GITHUB_TOKEN"] = github_token
            print("\n[+] GitHub subdomain discovery")
            print("    Token is passed via environment and is not saved by this script.")
            try:
                result = subprocess.run(
                    ["github-subdomains", "-d", domain, "-o", str(github_out)],
                    env=env, text=True, capture_output=True, timeout=300, check=False
                )
                if result.returncode:
                    print("[!] github-subdomains failed:", result.stderr[-1000:])
                else:
                    print("[✓] GitHub discovery finished.")
                    passive_files.append(github_out)
            except Exception as exc:
                print(f"[!] GitHub discovery failed: {exc}")
        else:
            print("[!] Skipped GitHub discovery: github-subdomains is not installed.")
    else:
        print("[i] Skipping GitHub subdomain discovery (no token supplied).")

    all_subs = base / "all_subs.txt"
    merge_files(passive_files, all_subs)
    normalize_subdomains(all_subs, domain)
    print(f"[i] Scope-filtered passive list: {all_subs}")

    if do_cloud_asn:
        if asn and re.fullmatch(r"AS\d+", asn):
            asn_out = base / "asn_results.txt"
            run_command("Amass ASN intelligence (verify each result is in scope)",
                        ["amass", "intel", "-asn", asn, "-o", str(asn_out)])
        elif asn:
            print("[!] ASN format should look like AS64500; skipping ASN enumeration.")
        else:
            print("[i] No ASN provided; skipping ASN enumeration.")
        if tool_exists("cloud_enum") and yes("Run CloudEnum keyword discovery for this domain?", False):
            run_command("CloudEnum (review every result for scope)",
                        ["cloud_enum", "-k", domain])
        else:
            print("[i] Skipping CloudEnum.")

    if do_active:
        resolved = base / "resolved_subs.txt"
        active_subs = base / "active_subs.txt"
        dnsx_out = base / "dnsx_results.txt"

        if resolvers and Path(resolvers).expanduser().is_file():
            if wordlist and Path(wordlist).expanduser().is_file():
                run_command("MassDNS resolution (requires a valid resolver list and wordlist)",
                            ["massdns", "-r", str(Path(resolvers).expanduser()), "-t", "A", "-o", "S",
                             "-w", str(base / "massdns_results.txt"), str(Path(wordlist).expanduser())])
            else:
                print("[i] Skipping MassDNS: provide an existing wordlist.")
            if tool_exists("shuffledns"):
                run_command("Shuffledns against the authorized root domain",
                            ["shuffledns", "-d", domain, "-list", str(all_subs),
                             "-r", str(Path(resolvers).expanduser()), "-o", str(active_subs)])
        else:
            print("[i] Skipping MassDNS/Shuffledns: provide an existing resolvers file.")
            active_subs.write_text(all_subs.read_text(encoding="utf-8"), encoding="utf-8")

        if not active_subs.exists():
            active_subs.write_text(all_subs.read_text(encoding="utf-8"), encoding="utf-8")

        run_command("DNSX resolution",
                    ["dnsx", "-l", str(active_subs), "-a", "-resp", "-o", str(dnsx_out)])

        live = base / "live_websites.txt"
        run_command("HTTPX probe (use only for in-scope hosts)",
                    ["httpx", "-l", str(active_subs), "-silent", "-title", "-sc", "-ip",
                     "-o", str(live)])

        if do_fuzz:
            if wordlist and Path(wordlist).expanduser().is_file():
                print("\n[!] Hostname fuzzing is active. Keep concurrency and request rates within program rules.")
                if yes("Run FFUF hostname fuzzing now?", False):
                    ffuf_out = base / "ffuf_subs.json"
                    run_command("FFUF hostname fuzzing",
                                ["ffuf", "-u", f"https://FUZZ.{domain}",
                                 "-w", str(Path(wordlist).expanduser()), "-t", "10",
                                 "-mc", "200,301,302,403", "-of", "json", "-o", str(ffuf_out)])
            else:
                print("[i] Skipping FFUF: provide an existing wordlist.")
    else:
        live = base / "live_websites.txt"
        print("[i] Active DNS and HTTP probing disabled.")
        # No assumption that a host is live; leave a seed list for optional crawling.
        live.write_text("".join(f"https://{x}\n" for x in read_lines(all_subs)), encoding="utf-8")

    if do_crawl:
        gau_out = base / "gau_urls.txt"
        wayback_out = base / "wayback_urls.txt"
        katana_out = base / "katana_urls.txt"
        gospider_dir = base / "gospider_output"
        gau_args = ["gau", "--subs", domain]
        run_pipe_to_file("GAU archived URL collection", gau_args, gau_out, timeout=300)
        run_pipe_to_file("Waybackurls archive collection", ["waybackurls", domain], wayback_out, timeout=300)

        # Crawlers are active. Ask again and use a modest depth.
        if do_active and yes("Run Katana crawling against listed hosts (active requests)?", False):
            run_command("Katana crawl", ["katana", "-list", str(live), "-jc", "-d", "2",
                                         "-silent", "-o", str(katana_out)], timeout=600)
        else:
            print("[i] Skipping Katana crawl.")
        if do_active and tool_exists("gospider") and yes("Run GoSpider against the root domain?", False):
            run_command("GoSpider crawl", ["gospider", "-s", f"https://{domain}", "-d", "2",
                                           "-o", str(gospider_dir)], timeout=600)
        else:
            print("[i] Skipping GoSpider.")

        merged_urls = base / "all_archived_urls.txt"
        merge_files([gau_out, wayback_out, katana_out], merged_urls)
        params_out = base / "parameter_urls.txt"
        params = [line for line in read_lines(merged_urls) if "=" in line]
        write_lines(params_out, params)
        print(f"[✓] URLs with query strings saved to {params_out}")

    if do_js:
        js_out = base / "javascript_urls.txt"
        candidates = []
        for filename in ("all_archived_urls.txt", "gau_urls.txt", "wayback_urls.txt", "katana_urls.txt"):
            for url in read_lines(base / filename):
                if re.search(r"\.js(?:[?#]|$)", url, re.I):
                    candidates.append(url)
        write_lines(js_out, candidates)
        print(f"\n[✓] JavaScript URL candidates saved to {js_out}")
        print("[i] Review these manually; do not use or test third-party secrets you may encounter.")

    print("\n=========================================================")
    print("Enumeration workflow finished.")
    print(f"Output directory: {base.resolve()}")
    print("Important: independently verify the scope of every discovered asset.")
    print("=========================================================")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[!] Cancelled by user.")
        raise SystemExit(130)
