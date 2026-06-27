/**
 * @module @mgreten/cli-process-audit
 *
 * Scan for running CLI coding agent processes (claude, opencode, amp, gemini),
 * classify each as healthy, orphaned, zombie, or long-running, and produce a
 * structured snapshot. Works on macOS and Linux by parsing `ps` output.
 */

import { z } from "npm:zod@4";

// ---------------------------------------------------------------------------
// Enums & schemas
// ---------------------------------------------------------------------------

/** Supported CLI agent providers to scan for. */
const ProviderEnum: z.ZodEnum<["claude", "opencode", "amp", "gemini"]> = z.enum(
  ["claude", "opencode", "amp", "gemini"],
);

/** Health classification for a discovered process. */
const HealthEnum: z.ZodEnum<
  ["healthy", "orphaned", "zombie", "long_running"]
> = z.enum([
  "healthy",
  "orphaned",
  "zombie",
  "long_running",
]);

const GlobalArgsSchema: z.ZodObject<{
  longRunningThresholdHours: z.ZodDefault<z.ZodNumber>;
  providers: z.ZodDefault<z.ZodArray<typeof ProviderEnum>>;
}> = z.object({
  longRunningThresholdHours: z.number().default(24).describe(
    "Hours of wall-clock elapsed time after which a process is flagged as long-running.",
  ),
  providers: z.array(ProviderEnum).default([
    "claude",
    "opencode",
    "amp",
    "gemini",
  ]).describe("Which CLI agent providers to scan for."),
});

const ProcessEntrySchema: z.ZodObject<{
  pid: z.ZodNumber;
  provider: typeof ProviderEnum;
  tty: z.ZodString;
  stat: z.ZodString;
  cpuTimeMinutes: z.ZodNumber;
  startedAt: z.ZodString;
  elapsedHours: z.ZodNumber;
  command: z.ZodString;
  health: typeof HealthEnum;
  healthReason: z.ZodString;
}> = z.object({
  pid: z.number().describe("Process ID."),
  provider: ProviderEnum.describe("Which CLI agent this process belongs to."),
  tty: z.string().describe("Controlling terminal (e.g. 'ttys006' or '??')."),
  stat: z.string().describe("Process state flags from ps (e.g. 'S+', 'Z')."),
  cpuTimeMinutes: z.number().describe("Cumulative CPU time in minutes."),
  startedAt: z.string().describe("ISO-8601 approximate start time."),
  elapsedHours: z.number().describe(
    "Wall-clock hours since the process started.",
  ),
  command: z.string().describe("Abbreviated command line."),
  health: HealthEnum.describe("Health classification."),
  healthReason: z.string().describe("Reason for the health classification."),
});

const SnapshotSchema: z.ZodObject<{
  scannedAt: z.ZodString;
  hostname: z.ZodString;
  totalFound: z.ZodNumber;
  healthyCount: z.ZodNumber;
  orphanedCount: z.ZodNumber;
  zombieCount: z.ZodNumber;
  longRunningCount: z.ZodNumber;
  processes: z.ZodArray<typeof ProcessEntrySchema>;
}> = z.object({
  scannedAt: z.string().describe("ISO-8601 timestamp of the scan."),
  hostname: z.string().describe("Machine hostname."),
  totalFound: z.number().describe("Total CLI agent processes discovered."),
  healthyCount: z.number().describe("Processes classified as healthy."),
  orphanedCount: z.number().describe("Processes classified as orphaned."),
  zombieCount: z.number().describe("Processes classified as zombie."),
  longRunningCount: z.number().describe(
    "Processes classified as long-running.",
  ),
  processes: z.array(ProcessEntrySchema).describe(
    "Per-process details and classification.",
  ),
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type CmdResult = { success: boolean; stdout: string; stderr: string };

/** Run a command and capture output. */
async function runCmd(cmd: string[]): Promise<CmdResult> {
  const command = new Deno.Command(cmd[0], {
    args: cmd.slice(1),
    stdout: "piped",
    stderr: "piped",
  });
  const output = await command.output();
  return {
    success: output.success,
    stdout: new TextDecoder().decode(output.stdout).trim(),
    stderr: new TextDecoder().decode(output.stderr).trim(),
  };
}

/** Process patterns that identify each provider's CLI. */
const PROVIDER_PATTERNS: Record<string, RegExp> = {
  claude: /(?:^|\/)claude(?:\s|$)/,
  opencode: /(?:^|\/)opencode(?:\s|$)/,
  amp: /(?:^|\/)amp(?:\s|$)/,
  gemini: /(?:^|\/)gemini(?:\s|$)/,
};

/** Parse ps TIME format (M:SS or H:MM:SS) into minutes. */
function parseCpuTime(timeStr: string): number {
  const parts = timeStr.split(":").map(Number);
  if (parts.length === 3) {
    return parts[0] * 60 + parts[1] + parts[2] / 60;
  }
  if (parts.length === 2) {
    return parts[0] + parts[1] / 60;
  }
  return 0;
}

/**
 * Parse a ps LSTART timestamp into an ISO string.
 * LSTART format: "Day Mon DD HH:MM:SS YYYY" (e.g. "Mon May 18 16:05:17 2026")
 */
function parseLstart(lstart: string): string {
  try {
    const d = new Date(lstart);
    if (!isNaN(d.getTime())) return d.toISOString();
  } catch { /* fall through */ }
  return new Date().toISOString();
}

/** Classify a process's health based on its state and elapsed time. */
function classifyHealth(
  stat: string,
  tty: string,
  elapsedHours: number,
  longRunningThresholdHours: number,
): { health: string; reason: string } {
  if (stat.startsWith("Z")) {
    return { health: "zombie", reason: "Process is in zombie state (Z)." };
  }

  const hasTty = tty !== "??" && tty !== "?";
  const isForeground = stat.includes("+");

  if (!hasTty) {
    return {
      health: "orphaned",
      reason: "No controlling terminal — detached from any TTY.",
    };
  }

  if (!isForeground) {
    return {
      health: "orphaned",
      reason:
        `Attached to ${tty} but not in foreground process group (stat: ${stat}).`,
    };
  }

  if (elapsedHours >= longRunningThresholdHours) {
    return {
      health: "long_running",
      reason: `Running for ${
        elapsedHours.toFixed(1)
      }h, exceeds ${longRunningThresholdHours}h threshold.`,
    };
  }

  return { health: "healthy", reason: `Foreground on ${tty}, stat ${stat}.` };
}

// ---------------------------------------------------------------------------
// Method context type
// ---------------------------------------------------------------------------

type MethodContext = {
  globalArgs: z.infer<typeof GlobalArgsSchema>;
  logger: {
    info: (msg: string, props?: Record<string, unknown>) => void;
    warning: (msg: string, props?: Record<string, unknown>) => void;
    error: (msg: string, props?: Record<string, unknown>) => void;
  };
  writeResource: (
    specName: string,
    instanceName: string,
    data: Record<string, unknown>,
  ) => Promise<Record<string, unknown>>;
};

// ---------------------------------------------------------------------------
// Model definition
// ---------------------------------------------------------------------------

/**
 * CLI Process Audit model.
 *
 * Scans the local machine for running CLI coding agent processes, classifies
 * each by health status, and writes a structured snapshot. Useful for detecting
 * orphaned sessions, zombies, and long-running agents that may have been
 * forgotten.
 *
 * ### Methods
 *
 * - **scan** — Discover all CLI agent processes and classify their health.
 */
export const model = {
  type: "@mgreten/cli-process-audit" as const,
  version: "2026.06.27.1" as const,
  globalArguments: GlobalArgsSchema,

  resources: {
    snapshot: {
      description:
        "Point-in-time snapshot of running CLI agent processes with health classifications.",
      schema: SnapshotSchema,
      lifetime: "30d" as const,
      garbageCollection: 50,
    },
  },

  methods: {
    scan: {
      description:
        "Discover all running CLI coding agent processes (claude, opencode, " +
        "amp, gemini), classify each as healthy, orphaned, zombie, or " +
        "long-running, and write a process snapshot.",
      arguments: z.object({
        providers: z.array(ProviderEnum).optional().describe(
          "Override the default provider list for this scan.",
        ),
      }),
      execute: async (
        args: { providers?: string[] },
        context: MethodContext,
      ): Promise<{ dataHandles: Record<string, unknown>[] }> => {
        const providers = (args.providers ??
          context.globalArgs.providers) as string[];
        const threshold = context.globalArgs.longRunningThresholdHours;

        const hostnameResult = await runCmd(["hostname"]);
        const hostname = hostnameResult.success
          ? hostnameResult.stdout
          : "unknown";

        // ps columns: PID, TTY, STAT, TIME (cpu), LSTART (5 fields), COMMAND
        // LSTART expands to "Day Mon DD HH:MM:SS YYYY" = 5 tokens
        const psResult = await runCmd([
          "ps",
          "axo",
          "pid,tty,stat,time,lstart,command",
        ]);

        if (!psResult.success) {
          throw new Error(`ps command failed: ${psResult.stderr}`);
        }

        const now = Date.now();
        type ProcessEntry = z.infer<typeof ProcessEntrySchema>;
        const processes: ProcessEntry[] = [];

        const lines = psResult.stdout.split("\n").slice(1); // skip header

        for (const line of lines) {
          const trimmed = line.trim();
          if (!trimmed) continue;

          // Split into tokens; LSTART takes 5 tokens, command is the rest
          const tokens = trimmed.split(/\s+/);
          if (tokens.length < 10) continue;

          const pid = parseInt(tokens[0], 10);
          const tty = tokens[1];
          const stat = tokens[2];
          const cpuTimeStr = tokens[3];
          const lstart = tokens.slice(4, 9).join(" ");
          const command = tokens.slice(9).join(" ");

          // Match against provider patterns
          let matchedProvider: string | null = null;
          for (const provider of providers) {
            const pattern = PROVIDER_PATTERNS[provider];
            if (pattern && pattern.test(command)) {
              matchedProvider = provider;
              break;
            }
          }
          if (!matchedProvider) continue;

          // Skip helper processes (Electron renderers, GPU helpers, etc.)
          if (
            command.includes("Helper") || command.includes("helper") ||
            command.includes("crashpad") || command.includes("ShipIt") ||
            command.includes("/Contents/Frameworks/")
          ) {
            continue;
          }

          const startedAt = parseLstart(lstart);
          const elapsedMs = now - new Date(startedAt).getTime();
          const elapsedHours = Math.max(0, elapsedMs / (1000 * 60 * 60));
          const cpuTimeMinutes = parseCpuTime(cpuTimeStr);

          const { health, reason } = classifyHealth(
            stat,
            tty,
            elapsedHours,
            threshold,
          );

          processes.push({
            pid,
            provider: matchedProvider as z.infer<typeof ProviderEnum>,
            tty,
            stat,
            cpuTimeMinutes: Math.round(cpuTimeMinutes * 100) / 100,
            startedAt,
            elapsedHours: Math.round(elapsedHours * 10) / 10,
            command: command.slice(0, 200),
            health: health as z.infer<typeof HealthEnum>,
            healthReason: reason,
          });
        }

        const counts = {
          healthy: 0,
          orphaned: 0,
          zombie: 0,
          long_running: 0,
        };
        for (const p of processes) {
          counts[p.health as keyof typeof counts]++;
        }

        const snapshot: z.infer<typeof SnapshotSchema> = {
          scannedAt: new Date().toISOString(),
          hostname,
          totalFound: processes.length,
          healthyCount: counts.healthy,
          orphanedCount: counts.orphaned,
          zombieCount: counts.zombie,
          longRunningCount: counts.long_running,
          processes,
        };

        const handle = await context.writeResource(
          "snapshot",
          `snapshot-${Date.now()}`,
          snapshot as unknown as Record<string, unknown>,
        );

        context.logger.info(
          "Scan complete: {total} processes ({healthy} healthy, {orphaned} orphaned, {zombie} zombie, {longRunning} long-running)",
          {
            total: processes.length,
            healthy: counts.healthy,
            orphaned: counts.orphaned,
            zombie: counts.zombie,
            longRunning: counts.long_running,
          },
        );

        return { dataHandles: [handle] };
      },
    },
  },
};
