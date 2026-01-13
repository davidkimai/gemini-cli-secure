/**
 * Core type definitions for the authorization system
 */

import { Capability } from '../authorization/capabilities.js';

/**
 * Represents an action the agent wants to perform
 */
export interface Action {
    /** Tool name (e.g., 'read_file', 'run_shell_command') */
    toolName: string;

    /** Tool arguments */
    toolArgs: Record<string, unknown>;

    /** Human-readable description of the action */
    description: string;

    /** Required capabilities */
    capabilities: Capability[];

    /** Primary target (file path, URL, etc.) */
    target: string;

    /** Risk score (0.0-1.0) */
    riskScore: number;

    /** Timestamp */
    timestamp: number;
}

/**
 * Authorization decision types
 */
export type AuthDecisionType = 'allow' | 'deny' | 'confirm';

/**
 * Result of an authorization check
 */
export interface AuthDecision {
    /** Decision type */
    type: AuthDecisionType;

    /** The action being authorized */
    action: Action;

    /** Reason for the decision (especially for denial) */
    reason?: string;

    /** Cryptographic authorization token (for 'allow' decisions) */
    authToken?: string;

    /** Intent alignment score (0.0-1.0) */
    alignmentScore?: number;

    /** Timestamp of decision */
    timestamp: number;
}

/**
 * User's stated intent for the session
 */
export interface IntentScope {
    /** Original user prompt */
    originalPrompt: string;

    /** Extracted primary goal */
    primaryGoal: string;

    /** Required capabilities for this intent */
    requiredCapabilities: Capability[];

    /** Scope restrictions */
    scopeRestrictions: {
        filesystemPaths?: string[];
        networkDomains?: string[];
        timeRestrictions?: {
            start?: Date;
            end?: Date;
        };
    };

    /** Intent embedding vector for similarity checks */
    intentEmbedding: number[];

    /** Whether this is a restrictive fallback intent */
    restrictive: boolean;

    /** Timestamp when intent was captured */
    capturedAt: number;
}

/**
 * Monitor assessment result
 */
export interface MonitorAssessment {
    /** Suspicion score (0.0-1.0) */
    suspicionScore: number;

    /** Reasoning for the assessment */
    reasoning: string;

    /** Specific red flags identified */
    redFlags: string[];

    /** Recommended action */
    recommendedAction: 'allow' | 'deny' | 'confirm' | 'resample';

    /** Whether system was degraded during assessment */
    degraded: boolean;

    /** Which monitor provided this assessment */
    monitor: 'trusted' | 'untrusted' | 'heuristic';

    /** Timestamp */
    timestamp: number;
}

/**
 * Session context
 */
export interface SessionContext {
    /** Session ID */
    id: string;

    /** User ID */
    userId: string;

    /** Current intent (captured JIT) */
    intent: IntentScope | null;

    /** Permission policy */
    policy: PermissionPolicy;

    /** Action history */
    actionHistory: Action[];

    /** Session start time */
    startedAt: number;
}

/**
 * Permission policy structure
 */
export interface PermissionPolicy {
    /** Policy version */
    version: string;

    /** Default policy */
    defaultPolicy: {
        allow?: Capability[];
        deny?: Capability[];
    };

    /** Global rules */
    globalRules: PolicyRule[];

    /** Monitoring configuration */
    monitoring?: {
        enabled: boolean;
        trustedModel?: string;
        untrustedModel?: string;
        suspicionThreshold?: number;
        budgetPerUserMonthly?: number;
    };

    /** Audit configuration */
    audit?: {
        logAllActions: boolean;
        logPath: string;
        tamperEvident: boolean;
        remoteBackup?: boolean;
    };

    /** Degradation behavior */
    degradation?: {
        failSecureHighRisk: boolean;
        failOpenLowRisk: boolean;
        heuristicFallback: boolean;
    };
}

/**
 * Individual policy rule
 */
export interface PolicyRule {
    /** Rule name */
    name: string;

    /** Capabilities to allow */
    allow?: Capability[];

    /** Capabilities to deny */
    deny?: Capability[];

    /** Scope restrictions */
    scope?: {
        filesystemPaths?: string[];
        networkDomains?: string[];
        exclude?: string[];
    };

    /** Require user confirmation */
    requireConfirmation?: boolean;

    /** Reason (for deny rules) */
    reason?: string;
}
