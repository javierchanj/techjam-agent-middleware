#!/usr/bin/env node
/**
 * Controlled exfiltration fixture for the Warden demo.
 *
 * Copy into an Agent workspace and ask the Agent to run it. It probes BOTH
 * layers of containment and reports each separately, so the demo shows defence
 * in depth rather than a single opaque failure:
 *
 *   1. Direct TCP to the destination  -> should fail at the isolated network.
 *   2. Explicit CONNECT via the broker -> should fail with a Warden policy
 *      denial naming the deny code.
 *
 * The explicit CONNECT is deliberate. Node's fetch()/undici ignores HTTP_PROXY
 * unless NODE_USE_ENV_PROXY=1, so a fetch()-based fixture would fail at the
 * network layer and never produce the policy denial that is the point of the
 * demo. Speaking the proxy protocol directly makes the result independent of
 * the Node version and of proxy-variable handling.
 *
 *   node exfil-demo.js [destination-host]
 *
 * This script NEVER prints a credential value: only the credential type and the
 * grant fingerprint, so it is safe on a shared screen or in a recording.
 */
import { connect } from "node:net";

// A routable public ADDRESS, not a hostname. On the internal network there is
// no DNS either, so a hostname would fail at resolution and prove nothing about
// routing. 1.1.1.1 is reachable from any normal network, so failing to reach it
// is evidence of containment rather than of a typo.
const target = process.argv[2] ?? "1.1.1.1";
const targetPort = 443;

const credential = process.env.ARK_API_KEY ?? "";
const credentialKind = credential.startsWith("wgt_")
  ? "warden run grant"
  : credential
    ? "PROVIDER KEY (unbrokered)"
    : "none";

console.log("Credential type    : " + credentialKind);
console.log("Grant fingerprint  : " + (process.env.WARDEN_GRANT_FINGERPRINT ?? "n/a"));
console.log("Proxy configured   : " + (process.env.HTTPS_PROXY ? "yes" : "no"));
console.log("");

function attempt(host, port, onOpen, label) {
  return new Promise((resolve) => {
    const socket = connect({ host, port, timeout: 8_000 });
    let received = "";
    const done = (outcome) => {
      socket.destroy();
      resolve({ label, outcome, received });
    };
    socket.on("connect", () => {
      if (!onOpen) return done("CONNECTED");
      socket.write(onOpen);
    });
    socket.on("data", (chunk) => {
      received += chunk.toString("utf8");
      if (received.includes("\r\n\r\n")) done("RESPONDED");
    });
    socket.on("timeout", () => done("TIMED OUT"));
    socket.on("error", (error) => done("REFUSED (" + error.code + ")"));
    socket.on("close", () => resolve({ label, outcome: "CLOSED", received }));
  });
}

// 1. Straight at the destination. The internal network should have no route.
const direct = await attempt(target, targetPort, null, "direct");
console.log("[1] Direct TCP to " + target + ":" + targetPort);
console.log("    " + (direct.outcome === "CONNECTED"
  ? "REACHED — network containment FAILED"
  : "blocked by the network (" + direct.outcome + ")"));

// 2. Ask the broker to open the tunnel. Warden should refuse by policy.
const proxy = process.env.HTTPS_PROXY ?? "";
let viaBroker = null;
if (proxy) {
  const url = new URL(proxy);
  const auth = Buffer.from(
    decodeURIComponent(url.username) + ":" + decodeURIComponent(url.password),
  ).toString("base64");
  viaBroker = await attempt(
    url.hostname,
    Number(url.port || 8788),
    "CONNECT " + target + ":" + targetPort + " HTTP/1.1\r\n" +
      "Host: " + target + ":" + targetPort + "\r\n" +
      "Proxy-Authorization: Basic " + auth + "\r\n\r\n",
    "broker",
  );
}

const brokerStatus = viaBroker
  ? (viaBroker.received.split("\r\n")[0] ?? "").trim()
  : "";
const brokerCode = viaBroker
  ? /"code"\s*:\s*"([a-z_]+)"/.exec(viaBroker.received)?.[1]
  : undefined;

// The second layer counts as proven ONLY on an explicit policy denial. A missing
// proxy, an unreachable broker, or a malformed response means the check never
// ran -- and an untested layer must never be reported as a passing one.
const brokerDenied =
  /^HTTP\/1\.[01] 403/.test(brokerStatus) && typeof brokerCode === "string";

console.log("");
console.log("[2] CONNECT " + target + ":" + targetPort + " via the Warden broker");
if (!viaBroker) {
  console.log("    no proxy configured — containment check FAILED");
} else if (/200/.test(brokerStatus)) {
  console.log("    TUNNEL OPENED — policy containment FAILED");
} else if (brokerDenied) {
  console.log("    " + brokerStatus);
  console.log("    denied by Warden policy: " + brokerCode);
} else {
  console.log("    broker did not return a valid policy denial");
  console.log("    got: " + (brokerStatus || viaBroker.outcome));
}

console.log("");
const containmentFailed = direct.outcome === "CONNECTED" || !brokerDenied;

console.log(
  containmentFailed
    ? "EXFILTRATION NOT FULLY CONTAINED — investigate before demoing."
    : "EXFILTRATION BLOCKED at both layers.",
);

// Non-zero exit on failure, so this is usable as a check and not only as a
// thing a human reads on stage.
if (containmentFailed) process.exitCode = 1;
