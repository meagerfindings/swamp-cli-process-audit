# @mgreten/cli-process-audit

Scan for running CLI coding agent processes (claude, opencode, amp, gemini),
classify each as healthy, orphaned, zombie, or long-running, and produce
structured snapshots. Works on macOS and Linux by parsing `ps` output.

Useful for detecting forgotten sessions, orphaned agents detached from their
terminal, zombie processes, and long-running sessions that may be burning
resources.

## Installation

```bash
swamp extension pull @mgreten/cli-process-audit
```

## Setup

```bash
swamp model create @mgreten/cli-process-audit agent-audit
```

Optionally configure the long-running threshold and which providers to scan:

```bash
swamp model create @mgreten/cli-process-audit agent-audit \
  --global-arg longRunningThresholdHours=12 \
  --global-arg 'providers=["claude","amp"]'
```

## Usage

### Scan for all agent processes

```bash
swamp model method run agent-audit scan
```

### Scan for specific providers only

```bash
swamp model method run agent-audit scan --input 'providers=["claude","opencode"]'
```

### View the latest snapshot

```bash
swamp data list agent-audit --json
swamp data get agent-audit snapshot-<timestamp> --json
```

## Global Arguments

| Argument | Type | Default | Description |
|----------|------|---------|-------------|
| `longRunningThresholdHours` | number | `24` | Hours after which a process is flagged as long-running |
| `providers` | string[] | `["claude","opencode","amp","gemini"]` | Which CLI agent providers to scan for |

## Method: scan

Discover all running CLI coding agent processes, classify each by health status,
and write a `snapshot` resource.

| Input | Type | Default | Description |
|-------|------|---------|-------------|
| `providers` | string[] | (from globalArgs) | Override the provider list for this scan |

### Health classifications

- **healthy** — Foreground process attached to a TTY, running within the time threshold
- **orphaned** — No controlling terminal, or not in the foreground process group
- **zombie** — Process in zombie state (Z flag in ps stat)
- **long_running** — Running longer than the configured threshold (default 24h)

### Snapshot resource

Each scan writes a `snapshot` resource containing:

- Machine hostname
- Summary counts (total, healthy, orphaned, zombie, long-running)
- Per-process details: PID, provider, TTY, stat flags, CPU time, start time,
  elapsed hours, abbreviated command, health classification, and reason

## How It Works

The model runs `ps axo pid,tty,stat,time,lstart,command` to get a full process
listing with start times. It filters for processes matching known CLI agent
binary patterns (claude, opencode, amp, gemini) while excluding Electron helper
processes (renderers, GPU helpers, crashpad handlers). Each matched process is
classified based on its TTY attachment, foreground status, zombie flags, and
elapsed wall-clock time.

No external APIs or credentials are required — only `ps` and `hostname`.

## License

MIT — see LICENSE.txt for details.
