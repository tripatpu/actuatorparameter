#!/usr/bin/env bash
#
# verify_hits.sh — confirm true-positive LFI / Spring Boot Actuator disclosures
#
# Takes a list of candidate URLs (e.g. ffuf's output, one full URL per line) and
# fetches each one, matching the RESPONSE BODY against content signatures. A URL is
# only reported as CONFIRMED when the body actually contains sensitive data — this
# filters out the 200-OK-but-empty / soft-404 noise that fuzzers produce.
#
# Usage:
#   ./verify_hits.sh -i urls.txt [-o confirmed.txt] [-t 40] [-T 10] [-H "Header: val"]
#
#   -i FILE   input file, one URL per line            (required)
#   -o FILE   write confirmed hits to FILE            (default: confirmed_hits.txt)
#   -t N      concurrent workers                      (default: 30)
#   -T N      per-request timeout in seconds          (default: 10)
#   -H HDR    extra header, repeatable (e.g. auth)    (optional)
#   -x URL    proxy (e.g. http://127.0.0.1:8080)      (optional)
#   -k        ignore TLS cert errors                  (optional)
#   -v        verbose: also print MISS lines
#
# Only run this against targets you are explicitly authorized to test.
#
set -u

# ---------- defaults ----------
INPUT=""
OUTFILE="confirmed_hits.txt"
WORKERS=30
TIMEOUT=10
PROXY=""
INSECURE=""
VERBOSE=0
declare -a EXTRA_HEADERS=()
UA="Mozilla/5.0 (compatible; lfi-actuator-verifier/1.0)"

# ---------- colors ----------
if [ -t 1 ]; then
  RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; RST=$'\033[0m'
else
  RED=""; GRN=""; YEL=""; DIM=""; RST=""
fi

usage() { grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

# ---------- args ----------
while getopts "i:o:t:T:H:x:kvh" opt; do
  case "$opt" in
    i) INPUT="$OPTARG" ;;
    o) OUTFILE="$OPTARG" ;;
    t) WORKERS="$OPTARG" ;;
    T) TIMEOUT="$OPTARG" ;;
    H) EXTRA_HEADERS+=("$OPTARG") ;;
    x) PROXY="$OPTARG" ;;
    k) INSECURE="-k" ;;
    v) VERBOSE=1 ;;
    h|*) usage ;;
  esac
done

[ -z "$INPUT" ] && { echo "${RED}[!] -i input file is required${RST}" >&2; usage; }
[ -f "$INPUT" ] && [ -r "$INPUT" ] || { echo "${RED}[!] cannot read input: $INPUT${RST}" >&2; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "${RED}[!] curl not found${RST}" >&2; exit 1; }

# build curl header args
declare -a HDR_ARGS=()
for h in "${EXTRA_HEADERS[@]:-}"; do [ -n "$h" ] && HDR_ARGS+=(-H "$h"); done
[ -n "$PROXY" ] && HDR_ARGS+=(-x "$PROXY")

export TIMEOUT UA PROXY INSECURE GRN RED YEL DIM RST VERBOSE
# pass header args to workers via a NUL-delimited temp file (arrays don't cross xargs)
HDRTMP="$(mktemp)"
if [ "${#HDR_ARGS[@]}" -gt 0 ]; then printf '%s\0' "${HDR_ARGS[@]}" > "$HDRTMP"; fi
export HDRTMP

# ---------- per-URL check (runs in subshell via xargs) ----------
check_one() {
  url="$1"
  [ -z "$url" ] && return 0

  # rebuild header args inside the worker
  HA=()
  if [ -s "$HDRTMP" ]; then mapfile -d '' -t HA < "$HDRTMP" 2>/dev/null; fi

  body="$(curl -s -S ${INSECURE} \
              --max-time "$TIMEOUT" \
              -A "$UA" \
              "${HA[@]}" \
              -w $'\n__HTTP_STATUS__:%{http_code}' \
              "$url" 2>/dev/null)"

  status="${body##*__HTTP_STATUS__:}"
  body="${body%$'\n'__HTTP_STATUS__:*}"
  [ -z "$status" ] && status="000"

  sig=""

  # ---- LFI signatures ----
  if printf '%s' "$body" | grep -Eq '^[a-z_][a-z0-9_-]*:[^:]*:[0-9]+:[0-9]+:'; then
    sig="LFI:/etc/passwd"
  elif printf '%s' "$body" | grep -Eq '^(root|daemon|bin):[^:]*:[0-9]*:[0-9]*:'; then
    sig="LFI:/etc/shadow"
  elif printf '%s' "$body" | grep -Eq 'Linux version [0-9]+\.[0-9]+'; then
    sig="LFI:/proc/version"
  elif printf '%s' "$body" | grep -Eq 'PATH=[^;]*(/usr/bin|/bin)'; then
    sig="LFI:/proc/self/environ"
  elif printf '%s' "$body" | grep -Eiq '\[fonts\]|\[extensions\]|# Copyright .* Microsoft'; then
    sig="LFI:windows-file"
  elif printf '%s' "$body" | grep -Eq 'BEGIN (RSA|OPENSSH|DSA|EC) PRIVATE KEY'; then
    sig="LFI:ssh-private-key"
  elif printf '%s' "$body" | grep -Eq '^[A-Za-z0-9+/]{200,}={0,2}$'; then
    sig="LFI:base64-source-leak"

  # ---- Spring Boot Actuator signatures ----
  elif printf '%s' "$body" | grep -Eq '"_links"[[:space:]]*:.*"self"'; then
    sig="ACTUATOR:index/_links"
  elif printf '%s' "$body" | grep -Eq '"(activeProfiles|propertySources)"[[:space:]]*:'; then
    sig="ACTUATOR:/env"
  elif printf '%s' "$body" | grep -Eq '"status"[[:space:]]*:[[:space:]]*"(UP|DOWN|OUT_OF_SERVICE|UNKNOWN)"'; then
    sig="ACTUATOR:/health"
  elif printf '%s' "$body" | grep -Eq '"(contexts|beans)"[[:space:]]*:.*"scope"'; then
    sig="ACTUATOR:/beans"
  elif printf '%s' "$body" | grep -Eq '"(dispatcherServlets|mappings)"[[:space:]]*:'; then
    sig="ACTUATOR:/mappings"
  elif printf '%s' "$body" | grep -Eq '"(contexts|beans)"[[:space:]]*:.*"prefix"'; then
    sig="ACTUATOR:/configprops"
  elif printf '%s' "$body" | grep -Eq '"(names|availableTags|measurements)"[[:space:]]*:'; then
    sig="ACTUATOR:/metrics"
  elif printf '%s' "$body" | grep -Eq '"traces"[[:space:]]*:.*"timestamp"'; then
    sig="ACTUATOR:/httptrace"
  elif printf '%s' "$body" | grep -Eq '"threads"[[:space:]]*:.*"threadName"'; then
    sig="ACTUATOR:/threaddump"
  elif printf '%s' "$body" | grep -Eq '"levels"[[:space:]]*:.*"loggers"[[:space:]]*:'; then
    sig="ACTUATOR:/loggers"
  elif printf '%s' "$body" | head -c 20 | grep -q 'JAVA PROFILE'; then
    sig="ACTUATOR:/heapdump"
  elif printf '%s' "$body" | grep -Eq '"agent"[[:space:]]*:.*"protocol"|"request".*"type".*"read"'; then
    sig="ACTUATOR:jolokia"
  fi

  if [ -n "$sig" ]; then
    printf '%s[CONFIRMED]%s %s[%s]%s %s %s\n' \
           "$GRN" "$RST" "$YEL" "$status" "$RST" "$sig" "$url"
    printf '%s\t%s\t%s\n' "$status" "$sig" "$url" >&3
  elif [ "$VERBOSE" = "1" ]; then
    printf '%s[miss] [%s] %s%s\n' "$DIM" "$status" "$url" "$RST"
  fi
}
export -f check_one

# ---------- run ----------
total="$(grep -cvE '^[[:space:]]*$' "$INPUT")"
echo "${YEL}[*] Verifying ${total} URLs with ${WORKERS} workers (timeout ${TIMEOUT}s)...${RST}"
: > "$OUTFILE"

# fd 3 -> outfile so workers can append confirmed hits without racing on stdout
grep -vE '^[[:space:]]*$' "$INPUT" \
  | xargs -P "$WORKERS" -I{} bash -c 'check_one "$@" 3>>"'"$OUTFILE"'"' _ {}

hits="$(wc -l < "$OUTFILE" | tr -d ' ')"
echo
echo "${GRN}[+] Done. ${hits} confirmed hit(s) written to ${OUTFILE}${RST}"
[ "$hits" -gt 0 ] && echo "${DIM}    format: <status>\\t<signature>\\t<url>${RST}"

rm -f "$HDRTMP"
