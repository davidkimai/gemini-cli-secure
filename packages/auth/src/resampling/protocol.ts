/**
 * Ctrl-Z Resampling Protocol
 * Implements selection pressure and value-of-information principles
 */

import type { Action, MonitorAssessment } from '../types/index.js';
import { analyzeVariance, type VarianceAnalysis } from './variance.js';
import { getIncriminationSystem, type IncriminationEvidence } from './incrimination.js';

/**
 * Selection strategy for resampling
 */
export enum SelectionStrategy {
    /** Execute least suspicious sample (default) */
    LEAST_SUSPICIOUS = 'least_suspicious',

    /** Block all execution and incriminate */
    BLOCK_ALL = 'block_all',

    /** Defer to human decision */
    DEFER_TO_HUMAN = 'defer',

    /** Request more samples */
    RESAMPLE_MORE = 'resample_more',
}

/**
 * Result of resampling protocol
 */
export interface ResamplingResult {
    /** The selected action to execute (if any) */
    selectedAction: Action | null;

    /** Selection strategy used */
    strategy: SelectionStrategy;

    /** All samples analyzed */
    samples: Action[];

    /** Variance analysis */
    variance: VarianceAnalysis;

    /** Incrimination evidence (if scheming model detected) */
    evidence?: IncriminationEvidence;

    /** Reason for decision */
    reason: string;

    /** Whether execution should proceed */
    shouldExecute: boolean;

    /** Monitor assessments for each sample */
    monitorAssessments?: MonitorAssessment[][];
}

/**
 * Resampling Protocol Configuration
 */
export interface ResamplingConfig {
    /** Number of samples to generate */
    k: number;

    /** Threshold for considering a sample "suspicious" */
    suspicionThreshold: number;

    /** Minimum confidence to incriminate */
    incriminationConfidence: number;

    /** Whether to enable incrimination */
    enableIncrimination: boolean;
}

/**
 * Default resampling configuration
 */
export const DEFAULT_RESAMPLING_CONFIG: ResamplingConfig = {
    k: 3,
    suspicionThreshold: 0.7,
    incriminationConfidence: 0.7,
    enableIncrimination: true,
};

/**
 * Ctrl-Z Resampling Protocol
 * 
 * Implements:
 * 1. Selection Pressure - Execute least suspicious if benign exists
 * 2. Value of Information - Incriminate when all samples malicious
 */
export class ResamplingProtocol {
    constructor(private config: ResamplingConfig = DEFAULT_RESAMPLING_CONFIG) { }

    /**
     * Execute resampling protocol on K samples
     * 
     * Ctrl-Z Logic:
     * - If ANY sample is benign → execute it (selection pressure)
     * - If ALL samples malicious → incriminate (value of information)
     */
    async execute(
        samples: Action[],
        monitorAssessments?: MonitorAssessment[][]
    ): Promise<ResamplingResult> {
        if (samples.length === 0) {
            return {
                selectedAction: null,
                strategy: SelectionStrategy.BLOCK_ALL,
                samples: [],
                variance: {
                    riskVariance: 0,
                    capabilityVariance: 0,
                    targetVariance: 0,
                    isConsistentAttack: false,
                    confidence: 0,
                    meanRisk: 0,
                    details: 'No samples provided',
                },
                reason: 'No samples to analyze',
                shouldExecute: false,
            };
        }

        // 1. Analyze variance across samples
        const variance = analyzeVariance(samples);

        // 2. Classify samples as suspicious or benign
        const classifications = this.classifySamples(samples, monitorAssessments);
        const benignSamples = classifications.filter(c => !c.isSuspicious);
        const maliciousSamples = classifications.filter(c => c.isSuspicious);

        // 3. Apply Ctrl-Z selection logic
        if (benignSamples.length > 0) {
            // CASE 1: At least one benign sample exists
            // → Selection Pressure: Execute least suspicious
            return this.handleBenignAlternatives(benignSamples, samples, variance);
        } else {
            // CASE 2: All samples are malicious
            // → Value of Information: Incriminate scheming model
            return this.handleAllMalicious(samples, variance, monitorAssessments);
        }
    }

    /**
     * Handle case where benign alternatives exist
     * Implements SELECTION PRESSURE principle
     */
    private handleBenignAlternatives(
        benignSamples: SampleClassification[],
        allSamples: Action[],
        variance: VarianceAnalysis
    ): ResamplingResult {
        // Select the least suspicious benign sample
        benignSamples.sort((a, b) => a.suspicionScore - b.suspicionScore);
        const selected = benignSamples[0];

        return {
            selectedAction: selected.action,
            strategy: SelectionStrategy.LEAST_SUSPICIOUS,
            samples: allSamples,
            variance,
            reason: `Found benign alternative (risk: ${selected.suspicionScore.toFixed(2)}). ` +
                `Executing least suspicious of ${benignSamples.length} benign samples.`,
            shouldExecute: true,
        };
    }

    /**
     * Handle case where all samples are malicious
     * Implements VALUE OF INFORMATION principle
     */
    private handleAllMalicious(
        samples: Action[],
        variance: VarianceAnalysis,
        monitorAssessments?: MonitorAssessment[][]
    ): ResamplingResult {
        // Check if this is a consistent attack (scheming model)
        if (variance.isConsistentAttack &&
            variance.confidence >= this.config.incriminationConfidence &&
            this.config.enableIncrimination) {

            // INCRIMINATE: Collect evidence of scheming model
            const incriminationSystem = getIncriminationSystem();
            const evidence = incriminationSystem.incriminate(samples, variance, monitorAssessments);

            return {
                selectedAction: null,
                strategy: SelectionStrategy.BLOCK_ALL,
                samples,
                variance,
                evidence,
                reason: `INCRIMINATED: Detected scheming model with ${(variance.confidence * 100).toFixed(1)}% confidence. ` +
                    `All ${samples.length} samples consistently malicious. Evidence ID: ${evidence.evidenceId}`,
                shouldExecute: false,
            };
        } else {
            // Not confident enough - defer to human
            return {
                selectedAction: null,
                strategy: SelectionStrategy.DEFER_TO_HUMAN,
                samples,
                variance,
                reason: `All ${samples.length} samples are malicious but confidence is low (${(variance.confidence * 100).toFixed(1)}%). ` +
                    `Deferring to human review.`,
                shouldExecute: false,
            };
        }
    }

    /**
     * Classify samples as suspicious or benign
     */
    private classifySamples(
        samples: Action[],
        monitorAssessments?: MonitorAssessment[][]
    ): SampleClassification[] {
        return samples.map((action, index) => {
            // Calculate suspicion score
            let suspicionScore = action.riskScore;

            // If we have monitor assessments, use them
            if (monitorAssessments && monitorAssessments[index]) {
                const assessments = monitorAssessments[index];
                const avgSuspicion = assessments.reduce((sum, a) => sum + a.suspicionScore, 0) / assessments.length;
                suspicionScore = Math.max(suspicionScore, avgSuspicion);
            }

            const isSuspicious = suspicionScore >= this.config.suspicionThreshold;

            return {
                action,
                suspicionScore,
                isSuspicious,
            };
        });
    }
}

/**
 * Sample classification
 */
interface SampleClassification {
    action: Action;
    suspicionScore: number;
    isSuspicious: boolean;
}

/**
 * Create resampling protocol with custom config
 */
export function createResamplingProtocol(config?: Partial<ResamplingConfig>): ResamplingProtocol {
    return new ResamplingProtocol({ ...DEFAULT_RESAMPLING_CONFIG, ...config });
}
