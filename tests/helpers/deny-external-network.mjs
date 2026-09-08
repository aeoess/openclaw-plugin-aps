// Preloaded into the Gateway child. Any outbound request to a host outside the
// loopback allowlist is recorded and rejected, so the regression FAILS on
// unexpected external network access instead of silently depending on it.
import { appendFileSync } from "node:fs";

const attemptsFile = process.env.APS_NETWORK_ATTEMPTS_FILE;
const allowed = new Set(["127.0.0.1", "localhost", "::1", "0.0.0.0"]);
const realFetch = globalThis.fetch;

globalThis.fetch = async (input, init) => {
  const raw = typeof input === "string" ? input : input instanceof URL ? input.href : input?.url;
  let host = "";
  try {
    host = new URL(String(raw)).hostname;
  } catch {
    host = "";
  }
  if (host && !allowed.has(host)) {
    if (attemptsFile) {
      appendFileSync(attemptsFile, `${host} ${String(raw)}\n`, "utf8");
    }
    throw new Error(`external network access denied in test harness: ${String(raw)}`);
  }
  return realFetch(input, init);
};
