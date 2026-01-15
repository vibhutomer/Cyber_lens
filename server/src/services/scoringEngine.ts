import type {
  ProviderExecutionResult,
  ProviderExecutionStatus,
} from "./providerExecutor";

export type ProviderVerdict = "benign" | "suspicious" | "malicious" | "unknown";
export type ProviderConfidence = "low" | "medium" | "high";
export type TrustLevel = "low" | "medium" | "high";
export type FinalVerdict = "benign" | "suspicious" | "malicious" | "unknown";

export interface ProviderSignal {
  provider: string;
  verdict: ProviderVerdict;
  confidence: ProviderConfidence;
  trustLevel: TrustLevel;
  status: ProviderExecutionStatus;
}

export interface ProviderTrustConfig {
  [providerName: string]: TrustLevel;
}

export interface ScoringConfig {
  providerTrust: ProviderTrustConfig;
  defaultTrustLevel: TrustLevel;
  singleProviderPenalty: number;
}

export interface ScoringInput {
  providers: ProviderExecutionResult<any>[];
  config?: ScoringConfig;
}

export interface NormalizedProviderResponse {
  provider_name: string;
  verdict: ProviderVerdict;
  confidence: ProviderConfidence;
  score?: number;
  summary?: string;
  tags?: string[];
}

export interface ScoringResult {
  finalScore: number | null;
  verdict: FinalVerdict;
  processedProviders: ProcessedProvider[];
  warnings: string[];
  meta: {
    totalProviders: number;
    successfulProviders: number;
    failedProviders: number;
    timedOutProviders: number;
    singleProviderMode: boolean;
    hasConflictingSignals: boolean;
  };
}

export interface ProcessedProvider {
  provider: string;
  status: ProviderExecutionStatus;
  normalizedScore: number | null;
  effectiveWeight: number | null;
  verdict: ProviderVerdict | null;
  confidence: ProviderConfidence | null;
  trustLevel: TrustLevel | null;
}

const VERDICT_SCORES: Record<ProviderVerdict, number> = {
  malicious: 100,
  suspicious: 60,
  unknown: 30,
  benign: 0,
};

const TRUST_WEIGHTS: Record<TrustLevel, number> = {
  high: 1.0,
  medium: 0.7,
  low: 0.5,
};

const CONFIDENCE_MULTIPLIERS: Record<ProviderConfidence, number> = {
  high: 1.0,
  medium: 0.75,
  low: 0.5,
};

const VERDICT_THRESHOLDS = {
  benign: { min: 0, max: 29 },
  suspicious: { min: 30, max: 69 },
  malicious: { min: 70, max: 100 },
} as const;

const DEFAULT_CONFIG: ScoringConfig = {
  providerTrust: {},
  defaultTrustLevel: "medium",
  singleProviderPenalty: 0.5,
};

interface TrustLookupResult {
  trustLevel: TrustLevel;
  isExplicit: boolean;
}

function getProviderTrustLevel(
  providerName: string,
  config: ScoringConfig,
): TrustLookupResult {
  const normalizedName = providerName.toLowerCase().trim();

  for (const [key, value] of Object.entries(config.providerTrust)) {
    if (key.toLowerCase().trim() === normalizedName) {
      return { trustLevel: value, isExplicit: true };
    }
  }

  return { trustLevel: config.defaultTrustLevel, isExplicit: false };
}

function normalizeVerdictToScore(verdict: ProviderVerdict): number {
  return VERDICT_SCORES[verdict] ?? VERDICT_SCORES.unknown;
}

function calculateEffectiveWeight(
  trustLevel: TrustLevel,
  confidence: ProviderConfidence,
): number {
  const trustWeight = TRUST_WEIGHTS[trustLevel];
  const confidenceMultiplier = CONFIDENCE_MULTIPLIERS[confidence];
  return trustWeight * confidenceMultiplier;
}

function mapScoreToVerdict(
  score: number,
  hasConflictingSignals: boolean,
): FinalVerdict {
  if (
    hasConflictingSignals &&
    score >= VERDICT_THRESHOLDS.suspicious.min &&
    score <= VERDICT_THRESHOLDS.suspicious.max
  ) {
    return "suspicious";
  }
  if (score >= VERDICT_THRESHOLDS.malicious.min) return "malicious";
  if (score >= VERDICT_THRESHOLDS.suspicious.min) return "suspicious";
  return "benign";
}

function normalizeConfidence(confidence: any): ProviderConfidence {
  if (typeof confidence === "string") {
    const lower = confidence.toLowerCase();
    if (lower === "high" || lower === "medium" || lower === "low") {
      return lower as ProviderConfidence;
    }
  }

  if (typeof confidence === "number") {
    if (confidence >= 70) return "high";
    if (confidence >= 40) return "medium";
    return "low";
  }

  return "medium";
}

function extractProviderSignal(
  result: ProviderExecutionResult<any>,
  config: ScoringConfig,
): { signal: ProviderSignal; isExplicitTrust: boolean } | null {
  if (result.status !== "success" || !result.data) {
    return null;
  }

  const data = result.data;
  const verdict: ProviderVerdict = data.verdict ?? "unknown";
  const confidence: ProviderConfidence = normalizeConfidence(data.confidence);
  const { trustLevel, isExplicit } = getProviderTrustLevel(
    result.provider,
    config,
  );

  return {
    signal: {
      provider: result.provider,
      verdict,
      confidence,
      trustLevel,
      status: result.status,
    },
    isExplicitTrust: isExplicit,
  };
}

export function computeScore(input: ScoringInput): ScoringResult {
  const { providers, config = DEFAULT_CONFIG } = input;

  const totalProviders = providers.length;
  let successfulProviders = 0;
  let failedProviders = 0;
  let timedOutProviders = 0;

  const processedProviders: ProcessedProvider[] = [];
  const validSignals: Array<{
    normalizedScore: number;
    effectiveWeight: number;
  }> = [];
  const warnings: string[] = [];

  for (const result of providers) {
    if (result.status === "success") {
      successfulProviders++;
    } else if (result.status === "timeout") {
      timedOutProviders++;
    } else {
      failedProviders++;
    }

    const extracted = extractProviderSignal(result, config);

    if (extracted) {
      const { signal, isExplicitTrust } = extracted;

      if (!isExplicitTrust) {
        warnings.push(
          `Provider "${signal.provider}" using default trust level "${config.defaultTrustLevel}"`,
        );
      }

      const normalizedScore = normalizeVerdictToScore(signal.verdict);
      const effectiveWeight = calculateEffectiveWeight(
        signal.trustLevel,
        signal.confidence,
      );

      validSignals.push({ normalizedScore, effectiveWeight });

      processedProviders.push({
        provider: result.provider,
        status: result.status,
        normalizedScore,
        effectiveWeight,
        verdict: signal.verdict,
        confidence: signal.confidence,
        trustLevel: signal.trustLevel,
      });
    } else {
      processedProviders.push({
        provider: result.provider,
        status: result.status,
        normalizedScore: null,
        effectiveWeight: null,
        verdict: null,
        confidence: null,
        trustLevel: null,
      });
    }
  }

  if (validSignals.length === 0) {
    return {
      finalScore: null,
      verdict: "unknown",
      processedProviders,
      warnings,
      meta: {
        totalProviders,
        successfulProviders,
        failedProviders,
        timedOutProviders,
        singleProviderMode: false,
        hasConflictingSignals: false,
      },
    };
  }

  const singleProviderMode = validSignals.length === 1;

  if (singleProviderMode) {
    warnings.push(
      "Single provider mode: reduced confidence due to lack of corroboration",
    );
  }

  const sumWeights = validSignals.reduce(
    (sum, s) => sum + s.effectiveWeight,
    0,
  );

  if (sumWeights === 0) {
    return {
      finalScore: null,
      verdict: "unknown",
      processedProviders,
      warnings,
      meta: {
        totalProviders,
        successfulProviders,
        failedProviders,
        timedOutProviders,
        singleProviderMode,
        hasConflictingSignals: false,
      },
    };
  }

  const sumWeightedScores = validSignals.reduce(
    (sum, s) => sum + s.normalizedScore * s.effectiveWeight,
    0,
  );

  let finalScore = Math.round(sumWeightedScores / sumWeights);

  if (singleProviderMode && config.singleProviderPenalty > 0) {
    const penalty = config.singleProviderPenalty;
    finalScore = Math.round(finalScore * (1 - penalty) + 30 * penalty);
  }

  const clampedScore = Math.max(0, Math.min(100, finalScore));

  const scores = validSignals.map((s) => s.normalizedScore);
  const hasHighThreat = scores.some((s) => s >= 70);
  const hasLowThreat = scores.some((s) => s <= 29);
  const hasConflictingSignals = hasHighThreat && hasLowThreat;

  const verdict = mapScoreToVerdict(clampedScore, hasConflictingSignals);

  return {
    finalScore: clampedScore,
    verdict,
    processedProviders,
    warnings,
    meta: {
      totalProviders,
      successfulProviders,
      failedProviders,
      timedOutProviders,
      singleProviderMode,
      hasConflictingSignals,
    },
  };
}
