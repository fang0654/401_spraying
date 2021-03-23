usage: 401_spray.py [-h] -u USERNAMES -p PASSWORDS -d DOMAIN -U URL
                    [-a ATTEMPTS] [-i INTERVAL] [--authtype {ntlm,basic}]
                    [--proxy PROXY] [--threads THREADS] [--output OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -u USERNAMES, --usernames USERNAMES
                        List of usernames to attack
  -p PASSWORDS, --passwords PASSWORDS
                        List of passwords to try
  -d DOMAIN, --domain DOMAIN
                        Domain name to append
  -U URL, --url URL     URL to authenticate against
  -a ATTEMPTS, --attempts ATTEMPTS
                        Number of attempts to try before sleeping. If your
                        lockout policy is 5 attempts per 10 minutes, then set
                        this to like 3
  -i INTERVAL, --interval INTERVAL
                        Number of minutes to sleep between attacks. If your
                        lockout policy is per 10 minutes, set this to like 11
  --authtype {ntlm,basic}
                        Authentication type - basic or ntlm. Note: You can't
                        use a proxy with NTLM
  --proxy PROXY         Proxy server to route traffic through
  --threads THREADS     Number of threads
  --output OUTPUT       File to write successful pairs to
