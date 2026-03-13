import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { toxicFlow } from "../src/rules/toxic-flow.js";
import type { ScannedFile } from "../src/types.js";

function makeFile(relativePath: string, content: string): ScannedFile {
  const ext = "." + relativePath.split(".").pop()!;
  return { path: `/fake/${relativePath}`, relativePath, content, lines: content.split("\n"), ext, context: "source" };
}

describe("toxic-flow: TF001 data leak", () => {
  it("detects untrusted + private + sink combination", () => {
    const config = makeFile("mcp-config.json", JSON.stringify({
      mcpServers: {
        "web-browser": {
          tools: [{ name: "fetch_url", description: "Fetches content from any user-provided URL" }],
        },
        "file-reader": {
          tools: [{ name: "read_file", description: "Reads files from the user's filesystem" }],
        },
        "messenger": {
          tools: [{ name: "send_message", description: "Sends a message via Slack or email" }],
        },
      },
    }));
    const findings = toxicFlow.run([config]);
    assert.ok(findings.some(f => f.message.includes("TF001")));
  });

  it("no toxic flow when only private data tools", () => {
    const config = makeFile("mcp-config.json", JSON.stringify({
      mcpServers: {
        "reader": {
          tools: [{ name: "read_file", description: "Reads local files" }],
        },
      },
    }));
    const findings = toxicFlow.run([config]);
    const tf = findings.filter(f => f.message.includes("TF001"));
    assert.equal(tf.length, 0);
  });
});

describe("toxic-flow: TF002 destructive", () => {
  it("detects untrusted + destructive combination", () => {
    const config = makeFile("mcp-config.json", JSON.stringify({
      mcpServers: {
        "browser": {
          tools: [{ name: "browse_web", description: "Browse any web page" }],
        },
        "admin": {
          tools: [{ name: "delete_files", description: "Delete files from the filesystem" }],
        },
      },
    }));
    const findings = toxicFlow.run([config]);
    assert.ok(findings.some(f => f.message.includes("TF002")));
  });
});

describe("toxic-flow: single dangerous tool", () => {
  it("detects single tool with multiple risky capabilities", () => {
    const config = makeFile("mcp-config.json", JSON.stringify({
      mcpServers: {
        "dangerous": {
          tools: [{
            name: "super_tool",
            description: "Fetches user-provided URL content, reads user private files, and sends email notifications",
          }],
        },
      },
    }));
    const findings = toxicFlow.run([config]);
    assert.ok(findings.some(f => f.message.includes("combines")));
  });
});

describe("toxic-flow: no config files", () => {
  it("returns empty for non-JSON files", () => {
    const file = makeFile("README.md", "This is a safe readme.");
    const findings = toxicFlow.run([file]);
    assert.equal(findings.length, 0);
  });
});
