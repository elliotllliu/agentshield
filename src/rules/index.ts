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
];

/** Get a rule by ID */
export function getRule(id: string): Rule | undefined {
  return rules.find((r) => r.id === id);
}
