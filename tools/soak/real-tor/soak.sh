#!/usr/bin/env bash
# tools/soak/real-tor/soak.sh — many-clients soak against the
# PUBLIC Tor network.
#
# Spawns N headless schat-cli instances (one `schat-cli daemon` process per
# instance, each with its own data dir; the CLI's SubprocessTor generates a
# per-instance torrc with SocksPort/ControlPort on free ports,
# CookieAuthentication 1, and its own DataDirectory — public authorities,
# NO TestingTorNetwork; the runner verifies every generated torrc).
#
# OPT-IN ONLY. This script refuses to run unless `--real-tor` is passed or
# SCHAT_REAL_TOR=1 is set. It is never part of `cargo test` or PR CI.
#
# Usage:
#   tools/soak/real-tor/soak.sh --real-tor [--instances N] [--duration HOURS]
#                               [--workdir DIR] [--interval SECS]
#                               [--offline-minutes MIN] [--flap-instances K]
#   tools/soak/real-tor/soak.sh --real-tor --smoke     # 2 instances, 10 min
#   tools/soak/real-tor/soak.sh --help
#
# Design notes (honest constraints of the current CLI surface):
# * One-shot commands (`send`, `edit`, `attach`) spawn their OWN tor on the
#   instance's data dir. Two tor processes must not share a DataDirectory,
#   and the store is held open by the running daemon, so the runner
#   CYCLES the sender's daemon: stop daemon -> one-shot send (own tor,
#   drains, exits) -> restart daemon. The onion address survives restarts
#   (the v3 service key is persisted in the instance keystore).
# * Delivery accounting: the sender ledger records (ts, msg_id) parsed from
#   `sent to relationship <rel> (msg_id <hex>)`; the receiver's daemon log
#   records `message: rel=<rel> id=<hex>`. A message counts delivered when
#   its msg_id appears in the receiver's log. Any received msg_id that is
#   NOT in the sent ledger is cross-talk and fails the gate. There is no
#   CLI-level ack API; this receiver-side log match is the accounting
#   method.
# * Daemon stdout has no timestamps, so the runner pipes each daemon log
#   through awk to prefix a unix timestamp on every line.
# * Offline windows: an instance's daemon is stopped (SIGTERM; the daemon's
#   own shutdown kills its tor subprocess) for --offline-minutes, then
#   restarted. Resync success = all messages sent to it while offline
#   appear in its log within the resync timeout after it returns.
# * Roaming/NEWNYM flap: --flap-instances instances run the daemon with
#   --simulate-network-flap (down 20 s / up 5 s cycle built into the CLI).
#   Descriptor recovery is measured from status samples at --interval
#   granularity.

set -euo pipefail

# ---------------------------------------------------------------- defaults
INSTANCES=20
DURATION_HOURS=48
WORKDIR=""
INTERVAL=300            # metrics sample period, seconds
OFFLINE_MINUTES=60      # resync-forcing offline window length
FLAP_INSTANCES=2        # instances started with --simulate-network-flap
SMOKE=0
REAL_TOR=0
PAIRS=10                # base pairs: (0,1), (2,3), ...
CROSS_EDGES=2           # extra cross edges on top of the base pairs
SEND_MIN_S=30           # per-pair send interval, seconds (with jitter)
SEND_MAX_S=120
RESYNC_TIMEOUT_S=1800   # how long to wait for post-offline delivery
FIRST_PAIR_TIMEOUT_S=600

usage() {
  sed -n '2,30p' "$0"
  exit "${1:-0}"
}

# ------------------------------------------------------------- arg parsing
while [[ $# -gt 0 ]]; do
  case "$1" in
    --instances)        INSTANCES="$2"; shift 2 ;;
    --duration)         DURATION_HOURS="$2"; shift 2 ;;
    --workdir)          WORKDIR="$2"; shift 2 ;;
    --interval)         INTERVAL="$2"; shift 2 ;;
    --offline-minutes)  OFFLINE_MINUTES="$2"; shift 2 ;;
    --flap-instances)   FLAP_INSTANCES="$2"; shift 2 ;;
    --pairs)            PAIRS="$2"; shift 2 ;;
    --cross-edges)      CROSS_EDGES="$2"; shift 2 ;;
    --real-tor)         REAL_TOR=1; shift ;;
    --smoke)            SMOKE=1; shift ;;
    --help|-h)          usage 0 ;;
    *) echo "error: unknown flag $1 (try --help)" >&2; exit 2 ;;
  esac
done

if [[ "${SMOKE}" == "1" ]]; then
  INSTANCES=2
  DURATION_HOURS=0.167   # 10 minutes
  INTERVAL=30
  OFFLINE_MINUTES=0.5    # 30 s
  FLAP_INSTANCES=0
  PAIRS=1
  CROSS_EDGES=0
  SEND_MIN_S=20
  SEND_MAX_S=60
  RESYNC_TIMEOUT_S=600
fi

# ------------------------------------------------------------- opt-in gate
# Standing rule: CI never touches the real Tor network. This runner exists
# for deliberate, attended runs only.
if [[ "${REAL_TOR}" != "1" && "${SCHAT_REAL_TOR:-0}" != "1" ]]; then
  echo "error: this soak runs instances against the PUBLIC Tor network." >&2
  echo "       It is opt-in only and never runs in cargo test or PR CI." >&2
  echo "       Pass --real-tor or set SCHAT_REAL_TOR=1 to proceed." >&2
  exit 2
fi

if (( INSTANCES < 2 )); then
  echo "error: --instances must be >= 2" >&2
  exit 2
fi

# ------------------------------------------------------------------- deps
need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' not found on PATH: $2" >&2; exit 1; }; }
need tor      "install the Tor daemon (the binary, not Tor Browser)"
need python3  "needed for metrics JSON and the final report"
need awk      "needed for log timestamping"
need cargo    "needed to build schat-cli (or set SCHAT_CLI_BIN to a prebuilt binary)"

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
WORKDIR="${WORKDIR:-${ROOT}/target/soak/${TS}}"
mkdir -p "${WORKDIR}"/{instances,metrics,ledger,pairing,locks}
WORKDIR="$(cd "${WORKDIR}" && pwd)"

CLI="${SCHAT_CLI_BIN:-}"
if [[ -z "${CLI}" ]]; then
  echo "== building schat-cli (release)"
  (cd "${ROOT}" && cargo build --release -p schat-cli)
  CLI="${ROOT}/target/release/schat-cli"
fi
[[ -x "${CLI}" ]] || { echo "error: schat-cli not executable at ${CLI}" >&2; exit 1; }

DURATION_S=$(awk -v h="${DURATION_HOURS}" 'BEGIN{printf "%d", h*3600}')
OFFLINE_S=$(awk -v m="${OFFLINE_MINUTES}" 'BEGIN{printf "%d", m*60}')
END_TS=$(( $(date +%s) + DURATION_S ))

echo "== soak: ${INSTANCES} instances, ${DURATION_HOURS} h, workdir ${WORKDIR}"
echo "== cli:  ${CLI}"

# ------------------------------------------------------------- state files
SENT_LEDGER="${WORKDIR}/ledger/sent.jsonl"     # one JSON per send attempt
EDITS_LEDGER="${WORKDIR}/ledger/edits.jsonl"
ATTACH_LEDGER="${WORKDIR}/ledger/attach.jsonl"
METRICS_JSONL="${WORKDIR}/metrics/metrics.jsonl"
TOPOLOGY="${WORKDIR}/pairing/topology.tsv"     # a_idx <TAB> rel_a <TAB> b_idx <TAB> rel_b
: > "${SENT_LEDGER}"; : > "${EDITS_LEDGER}"; : > "${ATTACH_LEDGER}"
: > "${METRICS_JSONL}"; : > "${TOPOLOGY}"

TRAFFIC_PIDS=()

inst_dir()  { echo "${WORKDIR}/instances/$(printf 'i%02d' "$1")"; }
inst_log()  { echo "$(inst_dir "$1")/daemon.log"; }
inst_pidf() { echo "$(inst_dir "$1")/daemon.pid"; }
inst_off()  { echo "$(inst_dir "$1")/log.offset"; }   # lines consumed before last (re)start

json() { # json key=value ... -> one JSON object line on stdout (python3 for safe quoting)
  python3 -c 'import json,sys; print(json.dumps(dict(kv.split("=",1) for kv in sys.argv[1:])))' "$@"
}

# ------------------------------------------------------- daemon lifecycle
# Daemon stdout is piped through awk to prefix every line with a unix
# timestamp (the CLI itself prints none). $! of the backgrounded pipeline
# is the awk pid; the CLI pid is captured via a fifo-free trick: we launch
# the CLI with process substitution so $! IS the CLI process.
start_daemon() { # idx
  local i="$1" d log extra=()
  d="$(inst_dir "$i")"; log="$(inst_log "$i")"
  mkdir -p "${d}/data"
  if (( i < FLAP_INSTANCES )); then
    extra+=(--simulate-network-flap)
  fi
  wc -l < "${log}" 2>/dev/null > "${d}/log.offset" || echo 0 > "${d}/log.offset"
  "${CLI}" daemon --data-dir "${d}/data" "${extra[@]}" \
    > >(awk '{ print systime(), $0; fflush() }' >> "${log}") 2>&1 &
  echo $! > "$(inst_pidf "$i")"
  echo "$(date +%s) daemon-start instance=${i} pid=$(cat "$(inst_pidf "$i")")" >> "${WORKDIR}/events.log"
}

stop_daemon() { # idx — SIGTERM first (daemon's own shutdown kills its tor)
  local i="$1" pidf pid
  pidf="$(inst_pidf "$i")"
  [[ -f "${pidf}" ]] || return 0
  pid="$(cat "${pidf}")"
  if kill -0 "${pid}" 2>/dev/null; then
    kill -TERM "${pid}" 2>/dev/null || true
    for _ in $(seq 1 30); do
      kill -0 "${pid}" 2>/dev/null || break
      sleep 0.5
    done
    kill -KILL "${pid}" 2>/dev/null || true
  fi
  # If we had to KILL, the tor subprocess may be orphaned; reap it by torrc path.
  pkill -f "$(inst_dir "$i")/data/tor/torrc" 2>/dev/null || true
  rm -f "${pidf}"
  echo "$(date +%s) daemon-stop instance=${i}" >> "${WORKDIR}/events.log"
}

wait_online() { # idx timeout_s — wait for a fresh `tor=online` status line
  local i="$1" timeout="$2" log off deadline
  log="$(inst_log "$i")"; off=$(( $(cat "$(inst_off "$i")" 2>/dev/null || echo 0) + 1 ))
  deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    if tail -n +"${off}" "${log}" 2>/dev/null | grep -q "status: tor=online"; then
      return 0
    fi
    sleep 2
  done
  echo "warning: instance ${i} did not report tor=online within ${timeout}s" >&2
  return 1
}

wait_log() { # idx pattern timeout_s — wait for a fresh log line matching pattern
  local i="$1" pat="$2" timeout="$3" log off deadline
  log="$(inst_log "$i")"; off=$(( $(cat "$(inst_off "$i")" 2>/dev/null || echo 0) + 1 ))
  deadline=$(( $(date +%s) + timeout ))
  while (( $(date +%s) < deadline )); do
    if tail -n +"${off}" "${log}" 2>/dev/null | grep -qE "${pat}"; then
      return 0
    fi
    sleep 2
  done
  return 1
}

verify_torrc_public() { # idx — the CLI generated <data>/tor/torrc; audit it
  local i="$1" torrc
  torrc="$(inst_dir "$1")/data/tor/torrc"
  for _ in $(seq 1 30); do [[ -f "${torrc}" ]] && break; sleep 1; done
  [[ -f "${torrc}" ]] || { echo "error: instance $1: no torrc generated at ${torrc}" >&2; return 1; }
  if grep -q "TestingTorNetwork" "${torrc}"; then
    echo "FATAL: instance $1 torrc contains TestingTorNetwork — refusing to touch the public network" >&2
    exit 1
  fi
  for want in "CookieAuthentication 1" "DataDirectory " "SocksPort 127.0.0.1:" "ControlPort 127.0.0.1:"; do
    grep -q "${want}" "${torrc}" || { echo "error: instance $1 torrc missing '${want}'" >&2; return 1; }
  done
}

# --------------------------------------------------------------- pairing
pair_instances() { # a_idx b_idx — offer/accept file flow, then accept-request
  local a="$1" b="$2" da db offer rel_b rel_a
  da="$(inst_dir "$a")/data"; db="$(inst_dir "$b")/data"
  offer="${WORKDIR}/pairing/offer-${a}-${b}.bin"

  "${CLI}" pair --data-dir "${da}" --offer --out "${offer}" > "${offer}.out" 2>&1
  "${CLI}" pair --data-dir "${db}" --accept "${offer}" > "${offer}.accept" 2>&1
  rel_b="$(awk '/^rel_id: /{print $2}' "${offer}.accept")"
  [[ -n "${rel_b}" ]] || { echo "error: pair ${a}->${b}: no rel_id from accept" >&2; return 1; }

  # B's daemon publishes the request; A's daemon must be up to receive it.
  wait_log "${a}" "request: rel=" "${FIRST_PAIR_TIMEOUT_S}" \
    || { echo "error: pair ${a}->${b}: no request reached ${a}" >&2; return 1; }
  rel_a="$("${CLI}" pair --data-dir "${da}" --requests | awk '/^request: /{sub(/^rel_id=/,"",$2); print $2}' | tail -1)"
  [[ -n "${rel_a}" ]] || { echo "error: pair ${a}->${b}: no pending request on ${a}" >&2; return 1; }
  "${CLI}" pair --data-dir "${da}" --accept-request --rel "${rel_a}" > /dev/null 2>&1

  printf '%s\t%s\t%s\t%s\n' "${a}" "${rel_a}" "${b}" "${rel_b}" >> "${TOPOLOGY}"
  echo "== paired i$(printf '%02d' "$a") <-> i$(printf '%02d' "$b")"
}

build_mesh() {
  local i j edges=()
  # Base pairs: (0,1), (2,3), ...
  for (( i=0; i+1 < INSTANCES && i/2 < PAIRS; i+=2 )); do
    edges+=("${i}:$((i+1))")
  done
  # Extra cross edges between adjacent pairs.
  for (( j=0; j < CROSS_EDGES; j++ )); do
    local x=$(( (2*j+1) % INSTANCES )) y=$(( (2*j+2) % INSTANCES ))
    edges+=("${x}:${y}")
  done
  # "10 pairs + 2 cross edges" gives 12 edges, which cannot give
  # 20 instances degree >= 2 (needs >= 20 edge-endpoints per side... i.e. at
  # least 20 edges for 20 nodes of degree 2). Enforce the actual requirement
  # — every instance has >= 2 relationships — by adding ring edges until the
  # degree floor holds.
  local -a deg
  for (( i=0; i < INSTANCES; i++ )); do deg[$i]=0; done
  for e in "${edges[@]}"; do
    deg[${e%%:*}]=$(( ${deg[${e%%:*}]} + 1 ))
    deg[${e##*:}]=$(( ${deg[${e##*:}]} + 1 ))
  done
  local ring=0
  while true; do
    local low=-1
    for (( i=0; i < INSTANCES; i++ )); do
      if (( deg[$i] < 2 )); then low=$i; break; fi
    done
    (( low < 0 )) && break
    local peer=$(( (low + 3 + ring) % INSTANCES ))
    (( peer == low )) && peer=$(( (low + 1) % INSTANCES ))
    edges+=("${low}:${peer}")
    deg[$low]=$(( ${deg[$low]} + 1 )); deg[$peer]=$(( ${deg[$peer]} + 1 ))
    ring=$(( ring + 1 ))
  done
  (( ring > 0 )) && echo "note: added ${ring} ring edges so every instance has >= 2 relationships (plan's 10+2 edges are arithmetically insufficient for N=${INSTANCES})"

  echo "${#edges[@]} edges" > "${WORKDIR}/pairing/edges.count"
  for e in "${edges[@]}"; do
    pair_instances "${e%%:*}" "${e##*:}"
  done
}

# ------------------------------------------------------------ traffic gen
# One background loop per topology edge. Sends are daemon-cycled (see
# header): stop the sender's daemon, one-shot send with its own tor,
# restart the daemon. A per-instance flock serializes cycles when an
# instance participates in multiple edges.
cycle_send() { # idx rel_id kind payload -> appends to the right ledger
  local i="$1" rel="$2" kind="$3" payload="$4" d out msg ts
  d="$(inst_dir "$i")/data"
  (
    flock -w 900 9 || { echo "warning: instance ${i} lock timeout" >&2; exit 1; }
    stop_daemon "$i"
    ts="$(date +%s)"
    case "${kind}" in
      text)
        out="$("${CLI}" send --data-dir "${d}" --rel "${rel}" --text "${payload}" 2>&1)" || true
        msg="$(echo "${out}" | awk '/\(msg_id /{gsub(/\)/,""); print $NF}')"
        if [[ -n "${msg}" ]]; then
          json ts="${ts}" from="${i}" rel="${rel}" msg_id="${msg}" text="${payload}" >> "${SENT_LEDGER}"
        else
          json ts="${ts}" from="${i}" rel="${rel}" error="$(echo "${out}" | tail -1)" >> "${SENT_LEDGER}.fail"
        fi
        ;;
      edit)
        out="$("${CLI}" edit --data-dir "${d}" --rel "${rel}" --msg-id "${payload}" --text "soak edit $(date +%s)" 2>&1)" || true
        msg="$(echo "${out}" | awk '/\(edit id /{gsub(/\)/,""); print $NF}')"
        [[ -n "${msg}" ]] && json ts="${ts}" from="${i}" rel="${rel}" target="${payload}" edit_id="${msg}" >> "${EDITS_LEDGER}"
        ;;
      attach)
        out="$("${CLI}" attach --data-dir "${d}" --rel "${rel}" --file "${payload}" --caption "soak attach" 2>&1)" || true
        msg="$(echo "${out}" | awk '/\(head /{gsub(/,/,""); print $3}')"
        [[ -n "${msg}" ]] && json ts="${ts}" from="${i}" rel="${rel}" head="${msg}" >> "${ATTACH_LEDGER}"
        ;;
    esac
    start_daemon "$i"
    wait_online "$i" 300 || true
  ) 9>"${WORKDIR}/locks/i$(printf '%02d' "$i").lock"
}

offline_window() { # idx — resync-forcing offline window (tor down with the daemon)
  local i="$1"
  (
    flock -w 900 9 || exit 1
    echo "$(date +%s) offline-begin instance=${i}" >> "${WORKDIR}/events.log"
    stop_daemon "$i"
    sleep "${OFFLINE_S}"
    start_daemon "$i"
    wait_online "$i" 600 || true
    echo "$(date +%s) offline-end instance=${i}" >> "${WORKDIR}/events.log"
  ) 9>"${WORKDIR}/locks/i$(printf '%02d' "$i").lock"
}

traffic_loop() { # a_idx rel_a b_idx rel_b
  local a="$1" rel_a="$2" b="$3" rel_b="$4" seq=0
  local attach_file="${WORKDIR}/payloads/tiny.png"
  while (( $(date +%s) < END_TS )); do
    sleep $(( SEND_MIN_S + RANDOM % (SEND_MAX_S - SEND_MIN_S + 1) ))
    (( $(date +%s) >= END_TS )) && break
    seq=$(( seq + 1 ))
    # Alternate direction each round so both sides exercise send.
    if (( seq % 2 == 1 )); then
      cycle_send "${a}" "${rel_a}" text "soak seq=${seq} edge=${a}-${b} $(date +%s)"
    else
      cycle_send "${b}" "${rel_b}" text "soak seq=${seq} edge=${a}-${b} $(date +%s)"
    fi
    # Occasional edit of the most recent text message we sent.
    if (( seq % 7 == 0 )); then
      local last
      last="$(awk -F'"msg_id": "' 'NF>1{split($2,a,"\""); print a[1]}' "${SENT_LEDGER}" 2>/dev/null | tail -1)"
      [[ -n "${last}" ]] && cycle_send "${a}" "${rel_a}" edit "${last}"
    fi
    # Occasional small attachment.
    if (( seq % 11 == 0 )); then
      cycle_send "${a}" "${rel_a}" attach "${attach_file}"
    fi
  done
}

offline_scheduler() { # stagger one offline window per instance per ~6 h
  local i=0
  while (( $(date +%s) < END_TS )); do
    sleep $(( 3600 + RANDOM % 3600 ))
    (( $(date +%s) + OFFLINE_S >= END_TS )) && break
    offline_window $(( i % INSTANCES ))
    i=$(( i + 1 ))
  done
}

# -------------------------------------------------------- metrics sampler
metrics_sampler() {
  while (( $(date +%s) < END_TS )); do
    sleep "${INTERVAL}"
    local i d log line
    for (( i=0; i < INSTANCES; i++ )); do
      log="$(inst_log "$i")"
      line="$(awk '/status: /{l=$0} END{print l}' "${log}" 2>/dev/null)"
      [[ -z "${line}" ]] && continue
      # line: "<ts> status: tor=online kill_switch=... outbox=N inbox=N last_error=- services=[inbox=Reachable(x.onion)]"
      python3 - "$i" "${line}" >> "${METRICS_JSONL}" <<'PY'
import json, re, sys
i, line = sys.argv[1], sys.argv[2]
m = re.match(r"(\d+) status: tor=(\S+).*?outbox=(\d+) inbox=(\d+) last_error=(\S+) services=\[(.*)\]", line)
if not m:
    sys.exit(0)
ts, tor, outbox, inbox, last_error, services = m.groups()
svc = {}
for part in services.split():
    sm = re.match(r"(\w+)=(\w+)\(([^)]*)\)", part)
    if sm:
        svc[sm.group(1)] = {"state": sm.group(2), "onion": sm.group(3)}
print(json.dumps({"ts": int(ts), "instance": int(i), "tor": tor,
                  "outbox": int(outbox), "inbox": int(inbox),
                  "last_error": None if last_error == "-" else last_error,
                  "services": svc}))
PY
    done
  done
}

# ------------------------------------------------------------ final report
write_report() {
  python3 - "${WORKDIR}" "${INSTANCES}" "${DURATION_HOURS}" "${RESYNC_TIMEOUT_S}" <<'PY'
import json, re, sys, glob, os, statistics, time

workdir, instances, hours = sys.argv[1], int(sys.argv[2]), sys.argv[3]
resync_timeout = int(sys.argv[4])

def read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try: out.append(json.loads(line))
                except json.JSONDecodeError: pass
    return out

sent = read_jsonl(f"{workdir}/ledger/sent.jsonl")
edits = read_jsonl(f"{workdir}/ledger/edits.jsonl")
attach = read_jsonl(f"{workdir}/ledger/attach.jsonl")
metrics = read_jsonl(f"{workdir}/metrics/metrics.jsonl")

# Receiver-side events from daemon logs: "<ts> message: rel=<rel> id=<hex>".
received, recv_edits, recv_attach = {}, {}, {}
gaps = 0
for log in glob.glob(f"{workdir}/instances/*/daemon.log"):
    inst = int(re.search(r"i(\d+)/daemon\.log$", log).group(1))
    with open(log, errors="replace") as f:
        for line in f:
            m = re.match(r"(\d+) message: rel=(\S+) id=([0-9a-f]+)", line)
            if m: received.setdefault(m.group(3), []).append((int(m.group(1)), inst, m.group(2)))
            m = re.match(r"(\d+) edited: rel=(\S+) id=([0-9a-f]+)", line)
            if m: recv_edits.setdefault(m.group(3), []).append((int(m.group(1)), inst))
            m = re.match(r"(\d+) attach-complete: rel=(\S+) head=([0-9a-f]+)", line)
            if m: recv_attach.setdefault(m.group(3), []).append((int(m.group(1)), inst))
            if "gap-detected:" in line: gaps += 1

for s in sent:
    if "ts" in s:
        s["ts"] = int(s["ts"])
sent_ids = {s["msg_id"]: s for s in sent if "msg_id" in s}
delivered = {mid: v for mid, v in received.items() if mid in sent_ids}
crosstalk = {mid: v for mid, v in received.items() if mid not in sent_ids}
latencies = sorted(min(ts for ts, _, _ in v) - sent_ids[mid]["ts"]
                   for mid, v in delivered.items())

def pct(p):
    if not latencies: return None
    k = (len(latencies) - 1) * p
    lo, hi = int(k), min(int(k) + 1, len(latencies) - 1)
    return round(latencies[lo] + (latencies[hi] - latencies[lo]) * (k - lo), 1)

n_sent = len(sent_ids)
delivery = (len(delivered) / n_sent) if n_sent else None

# Onion publish latency: daemon-start -> first inbox=Reachable status line.
publish_lat = []
for log in glob.glob(f"{workdir}/instances/*/daemon.log"):
    start = None
    with open(log, errors="replace") as f:
        for line in f:
            ts = int(line.split(" ", 1)[0]) if line[:1].isdigit() else None
            if "daemon-start" in line: pass
            if ts and "status:" in line and "inbox=Publishing" in line and start is None:
                start = ts
            if ts and start and "inbox=Reachable" in line:
                publish_lat.append(ts - start); start = None

# Offline resync: messages sent to an instance during its offline window
# that arrived within RESYNC timeout after offline-end.
events = []
if os.path.exists(f"{workdir}/events.log"):
    with open(f"{workdir}/events.log") as f:
        for line in f:
            m = re.match(r"(\d+) (\S+) instance=(\d+)", line)
            if m: events.append((int(m.group(1)), m.group(2), int(m.group(3))))
offline_total = offline_ok = 0
for ts, ev, inst in events:
    if ev != "offline-end": continue
    begin = max((t for t, e, i in events if e == "offline-begin" and i == inst and t <= ts), default=None)
    if begin is None: continue
    # rel ids for this instance from the topology
    rels = set()
    with open(f"{workdir}/pairing/topology.tsv") as tf:
        for row in tf:
            a, rel_a, b, rel_b = row.rstrip("\n").split("\t")
            if int(a) == inst: rels.add(rel_a)
            if int(b) == inst: rels.add(rel_b)
    for mid, s in sent_ids.items():
        if s["rel"] in rels and begin <= s["ts"] <= ts:
            offline_total += 1
            hits = [rts for rts, rinst, rrel in received.get(mid, []) if rinst == inst and rts <= ts + resync_timeout]
            if hits: offline_ok += 1

# Heal counts: degraded/dead samples followed by a later online sample.
heal = {}
stuck_dead = []
by_inst = {}
for row in metrics:
    by_inst.setdefault(row["instance"], []).append(row)
for inst, rows in by_inst.items():
    rows.sort(key=lambda r: r["ts"])
    bad = sum(1 for r in rows if r["tor"].startswith(("degraded", "dead")))
    healed = 0
    for j, r in enumerate(rows):
        if r["tor"].startswith(("degraded", "dead")) and any(x["tor"] == "online" for x in rows[j+1:]):
            healed += 1
    heal[inst] = {"degraded_or_dead_samples": bad, "recovered_samples": healed}
    if rows and rows[-1]["tor"].startswith("dead") and not rows[-1]["last_error"]:
        stuck_dead.append(inst)

gates = {
    "delivery_ge_99_5": (delivery is not None and delivery >= 0.995),
    "zero_crosstalk": (len(crosstalk) == 0),
    "no_stuck_dead_without_error": (len(stuck_dead) == 0),
}
report = {
    "generated_at": int(time.time()),
    "instances": instances,
    "duration_hours_requested": hours,
    "messages": {"sent": n_sent, "delivered": len(delivered),
                 "delivery_rate": delivery,
                 "latency_s": {"p50": pct(0.50), "p95": pct(0.95), "p99": pct(0.99)}},
    "edits": {"sent": len(edits), "applied": sum(len(v) for v in recv_edits.values())},
    "attachments": {"sent": len(attach), "complete": sum(len(v) for v in recv_attach.values())},
    "crosstalk_msgs": sorted(crosstalk),
    "gap_detected_events": gaps,
    "onion_publish_latency_s": {"samples": len(publish_lat),
                                "median": (statistics.median(publish_lat) if publish_lat else None)},
    "offline_resync": {"windows": sum(1 for _, e, _ in events if e == "offline-end"),
                       "msgs_sent_while_offline": offline_total,
                       "delivered_after_return": offline_ok,
                       "success_rate": (offline_ok / offline_total if offline_total else None)},
    "heal": heal,
    "stuck_dead_without_error": stuck_dead,
    "gates": gates,
    "accounting_method": ("sender ledger (msg_id from `send` output) matched against "
                          "receiver daemon logs (`message: rel= id=`); no CLI ack API exists"),
}
with open(f"{workdir}/report.json", "w") as f:
    json.dump(report, f, indent=2)

md = f"""# Soak report (skeleton -> notes/soak-v7.md)

- instances: {instances}, requested duration: {hours} h
- generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(report['generated_at']))}

## Delivery (gate: >= 99.5%)
- sent: {n_sent}, delivered: {len(delivered)}, rate: {delivery}
- method: {report['accounting_method']}

## Hot MSG latency (seconds)
- p50: {pct(0.50)}, p95: {pct(0.95)}, p99: {pct(0.99)}

## Cross-talk (gate: zero)
- unexpected msg_ids received: {len(crosstalk)}

## Resync after offline window
- windows: {report['offline_resync']['windows']}
- messages sent while offline: {offline_total}, delivered after return: {offline_ok}
- success rate: {report['offline_resync']['success_rate']}
- gap-detected events: {gaps}

## Onion publish latency (first Reachable)
- samples: {len(publish_lat)}, median: {report['onion_publish_latency_s']['median']} s

## Descriptor recovery after NEWNYM/roaming flap
- measured from metrics samples at the configured interval granularity; see metrics/metrics.jsonl

## TransportStatus heal counts
```json
{json.dumps(heal, indent=2)}
```

## Stuck Dead without surfaced error (gate: none)
- {stuck_dead}

## Gates
```json
{json.dumps(gates, indent=2)}
```
"""
with open(f"{workdir}/soak-report.md", "w") as f:
    f.write(md)
print(f"report: {workdir}/report.json")
print(f"report: {workdir}/soak-report.md")
print(json.dumps(gates))
PY
}

# ---------------------------------------------------------------- cleanup
cleanup() {
  trap - EXIT INT TERM
  echo "== shutting down"
  for pid in "${TRAFFIC_PIDS[@]:-}"; do
    [[ -n "${pid}" ]] && kill "${pid}" 2>/dev/null || true
  done
  for (( i=0; i < INSTANCES; i++ )); do
    stop_daemon "$i" || true
  done
  write_report || true
}
trap cleanup EXIT INT TERM

# ------------------------------------------------------------------- main
mkdir -p "${WORKDIR}/payloads"
export SOAK_WORKDIR="${WORKDIR}"
python3 - <<'PY'
import struct, zlib
# 1x1 valid PNG for attachment sends.
def chunk(t, d):
    c = t + d
    return struct.pack(">I", len(d)) + c + struct.pack(">I", zlib.crc32(c))
ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
raw = zlib.compress(b"\x00\x00\x00\x00")
png = (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", raw)
       + chunk(b"IEND", b""))
import os
open(os.path.join(os.environ["SOAK_WORKDIR"], "payloads/tiny.png"), "wb").write(png)
PY

echo "== starting ${INSTANCES} daemons (public Tor bootstrap; this takes a while)"
for (( i=0; i < INSTANCES; i++ )); do
  start_daemon "$i"
done
for (( i=0; i < INSTANCES; i++ )); do
  verify_torrc_public "$i"
done
echo "== all torrcs verified: public Tor, cookie auth, own DataDirectory, no TestingTorNetwork"
for (( i=0; i < INSTANCES; i++ )); do
  wait_online "$i" 600 || echo "warning: instance ${i} slow to bootstrap" >&2
done

echo "== building relationship mesh"
build_mesh

echo "== starting traffic generator + metrics sampler (end epoch ${END_TS})"
metrics_sampler & TRAFFIC_PIDS+=($!)
offline_scheduler & TRAFFIC_PIDS+=($!)
while IFS=$'\t' read -r a rel_a b rel_b; do
  traffic_loop "${a}" "${rel_a}" "${b}" "${rel_b}" & TRAFFIC_PIDS+=($!)
done < "${TOPOLOGY}"

while (( $(date +%s) < END_TS )); do
  sleep 60
done
echo "== duration elapsed"
