/** Severity levels for findings — three-tier risk system */
export type Severity = "high" | "medium" | "low";

/** Grade tiers for scoring system v2 */
export type Grade = "A" | "B" | "C" | "D" | "F";

/** A single dimension's score breakdown */
export interface DimensionScore {
  name: string;
  score: number; // 0-100
  deductions: { rule: string; amount: number; count: number }[];
}

/** Full scoring result from v2 scoring system */
export interface ScoreResult {
  overall: number;
  grade: Grade;
  gradeLabel: string;
  dimensions: {
    codeExec: DimensionScore;
    dataSafety: DimensionScore;
    supplyChain: DimensionScore;
    promptInjection: DimensionScore;
    codeQuality: DimensionScore;
  };
  bonus: number;
  bonusReasons: string[];
}

/** Metadata about the scanned project, used for bonus scoring */
export interface ProjectMeta {
  fileList: string[];
  totalLines: number;
  totalFiles: number;
  hasNetworkCalls: boolean;
}

/** Confidence levels for findings */
export type Confidence = "high" | "medium" | "low";

/** File context hints for reducing false positives */
export type FileContext = "test" | "deploy" | "config" | "docs" | "script" | "source";

/** A single security finding */
export interface Finding {
  rule: string;
  severity: Severity;
  file: string;
  line?: number;
  message: string;
  evidence?: string;
  /** Confidence level: high = confirmed issue, medium = likely issue, low = uncertain */
  confidence?: Confidence;
  /** If true, the finding is likely a false positive due to file context */
  possibleFalsePositive?: boolean;
  /** Why it might be a false positive */
  falsePositiveReason?: string;
}

/** Scan result for a directory */
export interface ScanResult {
  target: string;
  filesScanned: number;
  linesScanned: number;
  findings: Finding[];
  score: number;
  scoreResult?: ScoreResult;
  duration: number;
}

/** A scanner rule */
export interface Rule {
  id: string;
  name: string;
  description: string;
  run(files: ScannedFile[]): Finding[];
}

/** A file loaded for scanning */
export interface ScannedFile {
  filePath: string; // Absolute path to the file
  relativePath: string;
  content: string;
  lines: string[];
  ext: string;
  /** Detected file context for false positive reduction */
  context: FileContext;
  /** True if file imports a known safe SDK (e.g., @larksuiteoapi/, @aws-sdk/) */
  usesKnownSdk?: boolean;
  /** Names of known SDKs detected in imports */
  detectedSdks?: string[];
}

/** Parsed SKILL.md metadata */
export interface SkillMetadata {
  name?: string;
  description?: string;
  permissions?: string[];
  [key: string]: unknown;
}

/** Scan configuration from .agent-shield.yml */
export interface ScanConfig {
  rules?: {
    enable?: string[];
    disable?: string[];
  };
  severity?: Record<string, "high" | "medium" | "low">;
  failUnder?: number;
  ignore?: string[];
  /** List of safe domain regex patterns for network operations (e.g., ["^https://api\\.feishu\\.cn"]) */
  safeDomains?: string[];
  /** List of safe SDK package names to reduce false positives (e.g., ["@larksuiteoapi/node-sdk", "feishu-sdk"]) */
  safeSdks?: string[];
}

/** Per-agent security policy */
export interface AgentPolicy {
  /** Minimum grade required (A/B/C/D/F) */
  minGrade: Grade;
  /** Minimum numeric score */
  minScore?: number;
  /** Rules that must not trigger */
  blockRules?: string[];
  /** Maximum allowed severity */
  maxSeverity?: Severity;
}

/** Extended config with agent policies and provenance */
export interface AgentShieldConfig extends ScanConfig {
  /** Per-agent security policies */
  agents?: Record<string, AgentPolicy>;
  /** Default policy for agents not explicitly listed */
  defaultPolicy?: AgentPolicy;
  /** Provenance settings */
  provenance?: {
    /** Path to store hash manifests */
    manifestDir?: string;
    /** Auto-verify on scan */
    autoVerify?: boolean;
  };
}

/** Content hash manifest for provenance tracking */
export interface ProvenanceManifest {
  /** Skill/plugin name */
  name: string;
  /** Version string */
  version: string;
  /** ISO timestamp of manifest creation */
  createdAt: string;
  /** SHA-256 hash of concatenated file hashes */
  contentHash: string;
  /** Per-file hashes */
  files: Record<string, string>;
  /** Scan grade at time of manifest */
  grade?: Grade;
  /** Scan score at time of manifest */
  score?: number;
}
