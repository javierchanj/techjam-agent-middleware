import { describe, expect, it } from "vitest";
import { Redactor, redactedMessage } from "./redact.js";

const REAL_KEY = "ark_live_9f2c8b1a4d7e6f3a2b5c8d1e";

describe("Redactor", () => {
  it("removes every occurrence of a registered secret", () => {
    const redactor = new Redactor();
    redactor.register(REAL_KEY, "ark_api_key");
    const output = redactor.redactString(
      "curl -H 'x-key: " + REAL_KEY + "' upstream; retry with " + REAL_KEY,
    );
    expect(output).not.toContain(REAL_KEY);
    expect(output).toContain("[redacted:ark_api_key]");
  });

  it("catches credentials it was never told about, by shape", () => {
    const redactor = new Redactor();
    const output = redactor.redactString(
      "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payloadpayload and AKIAIOSFODNN7EXAMPLE",
    );
    expect(output).not.toContain("eyJhbGciOiJIUzI1NiJ9");
    expect(output).not.toContain("AKIAIOSFODNN7EXAMPLE");
  });

  it("redacts a minted grant token by shape even after it is unregistered", () => {
    const redactor = new Redactor();
    const token = "wgt_" + "a".repeat(43);
    redactor.register(token, "warden_grant_token");
    redactor.unregister(token);
    expect(redactor.redactString("proxy auth " + token)).not.toContain(token);
  });

  it("ignores short values so an empty config cannot blank out the ledger", () => {
    const redactor = new Redactor();
    redactor.register("", "empty");
    redactor.register("abc", "short");
    expect(redactor.registeredCount).toBe(0);
    expect(redactor.redactString("abc def")).toBe("abc def");
  });

  it("walks nested structures and Error instances", () => {
    const redactor = new Redactor();
    redactor.register(REAL_KEY, "ark_api_key");
    const output = redactor.redact({
      nested: [{ note: "key=" + REAL_KEY }],
      failure: new Error("upstream rejected " + REAL_KEY),
    });
    expect(JSON.stringify(output.nested)).not.toContain(REAL_KEY);
    expect(output.failure.message).not.toContain(REAL_KEY);
  });

  it("blanks authorization headers wholesale", () => {
    const redactor = new Redactor();
    const headers = redactor.redactHeaders({
      Authorization: "Bearer " + REAL_KEY,
      "proxy-authorization": "Basic Z3JhbnQ6d2d0X3NlY3JldA==",
      "content-type": "application/json",
    });
    expect(headers.authorization).toBe("[redacted:authorization_header]");
    expect(headers["proxy-authorization"]).toBe("[redacted:authorization_header]");
    expect(headers["content-type"]).toBe("application/json");
  });

  it("redacts thrown error messages on the run failure path", () => {
    const redactor = new Redactor();
    redactor.register(REAL_KEY, "ark_api_key");
    const message = redactedMessage(redactor, new Error("401 for " + REAL_KEY));
    expect(message).not.toContain(REAL_KEY);
  });
});

describe("real-world Ark key shapes", () => {
  // Ark issues hyphenated UUID keys. An earlier pattern required 12+ unbroken
  // alphanumerics after the prefix and matched none of them, so only the
  // exact-value registry was protecting the configured key.
  // Assembled at runtime rather than written as a literal. The fixture must have
  // the exact SHAPE Ark issues for this test to mean anything, but a literal of
  // that shape trips GitHub push protection -- and a fixture that cannot be
  // committed is a fixture that gets quietly deleted later.
  const HYPHENATED = ["ark", "00000000", "1111", "2222", "3333", "444444444444", "00000"].join("-");

  it("redacts a hyphenated Ark key it was never told about", () => {
    const redactor = new Redactor();
    const output = redactor.redactString("leaked " + HYPHENATED + " in a payload");
    expect(output).not.toContain(HYPHENATED);
    expect(output).toContain("[redacted:ark_api_key]");
  });

  it("still redacts the underscore-style key shape", () => {
    const redactor = new Redactor();
    expect(redactor.redactString("ark_live9f2c8b1a4d7e6f3a")).not.toContain("9f2c8b1a");
  });

  it("does not eat ordinary words that merely begin with ark", () => {
    const redactor = new Redactor();
    expect(redactor.redactString("the ark-of-the-covenant")).toContain("covenant");
    expect(redactor.redactString("arkansas is a state")).toBe("arkansas is a state");
  });
});
