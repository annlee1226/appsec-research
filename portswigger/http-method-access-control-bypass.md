# HTTP Method Confusion Bypassing Front-End Access Control

**Bug class:** Broken access control via HTTP verb tampering
**Impact:** Unprivileged user can grant themselves administrator privileges
**Platform:** PortSwigger Web Security Academy

## Target

A web application with an admin interface and two account tiers. The `/admin-roles` endpoint modifies user privileges and is intended to be reachable only by administrators. A standard account (`wiener:peter`) is provided.

## Vulnerability

Access control on `/admin-roles` only applies to POST requests. The endpoint accepts the same parameters via GET and processes them in full, without the access control check.

The flaw is treating the HTTP method as part of the authorization model. The method indicates request semantics, not security. Most server-side frameworks accept parameters identically regardless of method (PHP's `$_REQUEST`, default Flask and Express routes), so a handler written assuming POST-only invocation will process a GET request indistinguishably.

## Exploitation

### Step 1: Map the privileged action from the admin session

Logged in as `administrator` and captured the request the admin interface uses to upgrade a user:

```http
POST /admin-roles HTTP/2
Host: TARGET.web-security-academy.net
Cookie: session=<admin_session>
Content-Type: application/x-www-form-urlencoded

username=wiener&action=upgrade
```

### Step 2: Confirm the standard user cannot reach the admin interface

Logged in as `wiener` and navigated to `/admin`. Access denied, as expected.

### Step 3: Send the privileged action as a GET request

Sent the same parameters as a GET, with `wiener`'s session cookie:

```http
GET /admin-roles?username=wiener&action=upgrade HTTP/2
Host: TARGET.web-security-academy.net
Cookie: session=<wiener_session>
```

The server processed the upgrade.

### Step 4: Confirm the privilege change

Requested `/admin` as `wiener` and received the admin interface. The role change persisted server-side.

## Reasoning notes

First attempted to bypass routing with `X-Original-URL: /admin` and `X-Original-URL: /admin-roles`. Both failed. The application does not honor that header here, which ruled out routing-layer bypasses and pointed at the request itself.

The actual bypass came from noticing what the front-end was filtering. The admin interface only ever issues POSTs to `/admin-roles`, so the protection is naturally phrased as "block non-admin POSTs to /admin-roles." That phrasing contains the flaw. The block is on POST. The action is on the endpoint. If the back-end accepts the action via any method, the gate is narrower than the set of requests that achieve the outcome.

The generalization: HTTP methods are conventions about request semantics, not security boundaries. Any control that gates on method assumes the back-end rejects the action when invoked through any other method, and that assumption needs verification at the handler.

## Root cause

The access control layer and the request handler disagree on what defines a "privileged request." The access control layer defines it as `POST /admin-roles`. The handler defines it as `any method to /admin-roles with the right parameters`. The bypass lives in the gap.

This recurs whenever framework-default request handling is more permissive than the security model assumes. Common contributors: PHP's `$_REQUEST` superglobal, Express routes registered without a method, Flask routes omitting `methods` on `@app.route`.

## Remediation

- **Enforce authorization at the handler, not at the verb.** The same check should fire regardless of method.
- **Restrict accepted methods at the route definition.** Flask: `@app.route('/admin-roles', methods=['POST'])`. Express: `app.post('/admin-roles', ...)`. Default-permissive routing is the failure mode.
- **Treat HTTP methods as semantic hints, not security primitives.** Flag any access control logic that branches on method during code review.

## References

- [PortSwigger: Method-based access control can be circumvented](https://portswigger.net/web-security/access-control/lab-method-based-access-control-can-be-circumvented)
- [OWASP: Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html)
- [OWASP API Security Top 10: Broken Function Level Authorization](https://owasp.org/API-Security/editions/2023/en/0xa5-broken-function-level-authorization/)
