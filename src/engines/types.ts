/**
 * Multi-engine adapter interface.
 *
 * Each adapter wraps an external security scanner,
 * normalizing its output into a common finding format.
 */

export interface EngineFinding {
  engine: string;
  severity: "high" | "medium" | "low" | "info";
  file: string;
  line?: number;
  rule: string;
  message: string;
  evidence?: string;
  confidence?: number;
  /** Original category from the engine (unmapped) */
  category?: string;
}

export interface EngineResult {
  engine: string;
  displayName: string;
  version?: string;
  available: boolean;
  /** null if engine not available */
  findings: EngineFinding[] | null;
  error?: string;
  durationMs?: number;
  focus: string;
}

export interface EngineAdapter {
  /** Unique engine identifier */
  id: string;
  /** Display name for reports */
  displayName: string;
  /** One-line description of what this engine focuses on */
  focus: string;
  /** URL for more info */
  url: string;

  /** Check if the engine is installed/available */
  isAvailable(): Promise<boolean>;

  /** Install instructions (shown when engine is missing) */
  installInstructions(): string;

  /** Run the scan and return normalized findings */
  scan(targetDir: string): Promise<EngineResult>;
}

/**
 * Aggregated result from multiple engines.
 */
export interface AggregatedResult {
  target: string;
  engines: EngineResult[];
  /** Findings that appear in multiple engines (cross-validated) */
  crossValidated: CrossValidatedFinding[];
  /** All findings, deduplicated, with engine attribution */
  allFindings: EngineFinding[];
  totalEngines: number;
  availableEngines: number;
  durationMs: number;
}

export interface CrossValidatedFinding {
  /** Normalized key for grouping (file + line + category) */
  key: string;
  file: string;
  line?: number;
  severity: "high" | "medium" | "low" | "info";
  message: string;
  /** Which engines detected this */
  detectedBy: string[];
  /** Total engines that scanned this file */
  totalEngines: number;
  /** Agreement ratio (detectedBy.length / totalEngines) */
  agreement: number;
}
