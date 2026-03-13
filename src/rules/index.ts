import type { Rule } from "../types.js";
import { sensitiveReadRule } from "./sensitive-read.js";
import { backdoorRule } from "./backdoor.js";
import { dataExfilRule } from "./data-exfil.js";
import { privilegeRule } from "./privilege.js";
import { supplyChainRule } from "./supply-chain.js";
import { obfuscationRule } from "./obfuscation.js";
import { envLeakRule } from "./env-leak.js";
import { cryptoMiningRule } from "./crypto-mining.js";
import { reverseShellRule } from "./reverse-shell.js";
import { typosquattingRule } from "./typosquatting.js";
import { hiddenFilesRule } from "./hidden-files.js";
import { excessivePermsRule } from "./excessive-perms.js";
import { phoneHomeRule } from "./phone-home.js";
import { credentialHardcodeRule } from "./credential-hardcode.js";
import { networkSsrfRule } from "./network-ssrf.js";
import { mcpManifestRule } from "./mcp-manifest.js";
import { promptInjection } from "./prompt-injection.js";
import { toolShadowing } from "./tool-shadowing.js";
import { skillRisks } from "./skill-risks.js";
import { toxicFlow } from "./toxic-flow.js";
import { pythonSecurityRule } from "./python-security.js";
import { crossFileRule } from "./cross-file.js";
import { attackChainRule } from "./attack-chain.js";
import { multilangInjectionRule } from "./multilang-injection.js";
import { descriptionIntegrityRule } from "./description-integrity.js";
import { pythonAstRule } from "./python-ast.js";

/** All registered rules */
export const rules: Rule[] = [
  // Original 5
  dataExfilRule,
  backdoorRule,
  privilegeRule,
  supplyChainRule,
  sensitiveReadRule,
  // New 10
  obfuscationRule,
  envLeakRule,
  cryptoMiningRule,
  reverseShellRule,
  typosquattingRule,
  hiddenFilesRule,
  excessivePermsRule,
  phoneHomeRule,
  credentialHardcodeRule,
  networkSsrfRule,
  mcpManifestRule,
  // Prompt injection & tool shadowing
  promptInjection,
  toolShadowing,
  // Skill risk assessment
  skillRisks,
  // Toxic flow analysis
  toxicFlow,
  // Python-specific security
  pythonSecurityRule,
  // Cross-file correlation analysis
  crossFileRule,
  // Multi-step attack chain detection
  attackChainRule,
  // Multi-language injection + advanced poisoning
  multilangInjectionRule,
  // Description vs code integrity check
  descriptionIntegrityRule,
  // Python AST deep analysis
  pythonAstRule,
];

/** Get a rule by ID */
export function getRule(id: string): Rule | undefined {
  return rules.find((r) => r.id === id);
}
