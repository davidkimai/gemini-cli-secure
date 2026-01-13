/**
 * Core Authorization Engine
 * Implements capability-based access control with intent alignment
 */

import { minimatch } from 'minimatch';
import { Capability, HIGH_RISK_CAPABILITIES } from './capabilities.js';
import { generateAuthToken } from './token-binding.js';
import type {
    Action,
    AuthDecision,
    IntentScope,
    PermissionPolicy,
    PolicyRule,
} from '../types/index.js';

/**
 * Authorization Engine
 */
export class AuthorizationEngine {
    constructor(private policy: PermissionPolicy) { }

    /**
     * Main authorization logic
     */
    async authorize(
        action: Action,
        intentScope: IntentScope | null
    ): Promise<AuthDecision> {
        const timestamp = Date.now();

        // Calculate intent alignment first if intent exists (needed for all decisions)
        let alignmentScore: number | undefined;
        if (intentScope && !intentScope.restrictive) {
            alignmentScore = this.checkAlignment(action, intentScope);
        }

        // Step 1: Explicit deny rules (highest priority)
        if (this.isExplicitlyDenied(action)) {
            const rule = this.getDenyRule(action);
            return {
                type: 'deny',
                action,
                reason: rule?.reason || 'Explicitly denied by policy',
                alignmentScore,
                timestamp,
            };
        }

        // Step 2: Capability check
        if (!this.isCapabilityAllowed(action.capabilities)) {
            return {
                type: 'deny',
                action,
                reason: 'Required capabilities not permitted by policy',
                alignmentScore,
                timestamp,
            };
        }

        // Step 3: Scope restrictions
        if (!this.isScopeValid(action)) {
            return {
                type: 'deny',
                action,
                reason: `Out of scope: ${action.target}`,
                alignmentScore,
                timestamp,
            };
        }

        // Step 4: Intent alignment checks
        if (intentScope && !intentScope.restrictive && alignmentScore !== undefined) {
            if (alignmentScore < 0.5) {
                return {
                    type: 'deny',
                    action,
                    reason: 'Action drifts significantly from stated intent',
                    alignmentScore,
                    timestamp,
                };
            } else if (alignmentScore < 0.8) {
                return {
                    type: 'confirm',
                    action,
                    reason: 'Uncertain intent alignment - user confirmation required',
                    alignmentScore,
                    timestamp,
                };
            }
        }

        // Step 5: Confirmation required?
        if (this.requiresConfirmation(action)) {
            return {
                type: 'confirm',
                action,
                reason: 'Policy requires user confirmation for this action',
                alignmentScore,
                timestamp,
            };
        }

        // Generate cryptographic token binding
        const authToken = generateAuthToken(action);

        return {
            type: 'allow',
            action,
            authToken,
            alignmentScore,
            timestamp,
        };
    }

    /**
     * Check if capabilities are allowed by policy
     */
    private isCapabilityAllowed(capabilities: Capability[]): boolean {
        const { defaultPolicy, globalRules } = this.policy;

        for (const capability of capabilities) {
            // Check default deny
            if (defaultPolicy.deny?.includes(capability)) {
                // Check if any rule explicitly allows it
                const explicitlyAllowed = globalRules.some(
                    rule => rule.allow?.includes(capability) && !rule.deny?.includes(capability)
                );
                if (!explicitlyAllowed) {
                    return false;
                }
            }

            // Check default allow
            if (defaultPolicy.allow && !defaultPolicy.allow.includes(capability)) {
                // Check if denied by default and not explicitly allowed
                const explicitlyAllowed = globalRules.some(
                    rule => rule.allow?.includes(capability)
                );
                if (!explicitlyAllowed) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
   * Check if action target is within allowed scope
   */
    private isScopeValid(action: Action): boolean {
        // Find rules that define scope for this action's capabilities
        const scopedRules = this.policy.globalRules.filter(rule =>
            rule.scope && action.capabilities.some(cap => rule.allow?.includes(cap))
        );

        // If there are scoped rules for this capability, action MUST comply with at least one
        if (scopedRules.length > 0) {
            // Check if ANY scoped rule allows the action (OR logic)
            for (const rule of scopedRules) {
                if (!rule.scope) continue;

                // Check filesystem paths
                if (rule.scope.filesystemPaths) {
                    const isFileOp = action.capabilities.some(cap =>
                        cap.startsWith('filesystem.')
                    );

                    if (isFileOp) {
                        const inScope = rule.scope.filesystemPaths.some(pattern =>
                            minimatch(action.target, pattern, { dot: true })
                        );

                        const excluded = rule.scope.exclude?.some(pattern =>
                            minimatch(action.target, pattern, { dot: true })
                        ) ?? false;

                        // If this rule allows the action (in scope and not excluded), return true
                        if (inScope && !excluded) {
                            return true;
                        }
                    }
                }

                // Check network domains
                if (rule.scope.networkDomains) {
                    const isNetworkOp = action.capabilities.some(cap =>
                        cap.startsWith('network.')
                    );

                    if (isNetworkOp) {
                        const inScope = rule.scope.networkDomains.some(pattern => {
                            try {
                                const url = new URL(action.target);
                                return minimatch(url.hostname, pattern);
                            } catch {
                                return minimatch(action.target, pattern);
                            }
                        });

                        if (inScope) {
                            return true;
                        }
                    }
                }
            }

            // No scoped rule allowed the action - deny
            return false;
        }

        // No scope restrictions for this capability - allow
        return true;
    }

    /**
     * Check intent alignment using multi-signal approach
     */
    private checkAlignment(action: Action, intentScope: IntentScope): number {
        // Signal 1: Capability alignment (PRIMARY - 50%)
        const requiredCaps = new Set(action.capabilities);
        const expectedCaps = new Set(intentScope.requiredCapabilities);
        const unexpectedCaps = new Set(
            [...requiredCaps].filter(cap => !expectedCaps.has(cap))
        );

        let capScore = 1.0;
        if (unexpectedCaps.size > 0) {
            // Check if unexpected caps are high-risk
            const hasHighRisk = [...unexpectedCaps].some(cap =>
                HIGH_RISK_CAPABILITIES.has(cap)
            );

            if (hasHighRisk) {
                return 0.0; // Hard deny for high-risk capability mismatch
            }
            capScore = 0.3; // Low score for unexpected capabilities
        }

        // Signal 2: Embedding similarity (30%)
        // TODO: Implement actual embedding similarity when we add embeddings
        const embeddingSim = 0.8; // Placeholder

        // Signal 3: Scope-based drift detection (20%)
        let driftScore = 1.0;
        if (unexpectedCaps.size === 0) {
            // Only check drift if caps align
            if (action.target && intentScope.scopeRestrictions) {
                const paths = intentScope.scopeRestrictions.filesystemPaths || [];
                const domains = intentScope.scopeRestrictions.networkDomains || [];

                const inScope = [...paths, ...domains].some(pattern =>
                    minimatch(action.target, pattern)
                );

                driftScore = inScope ? 1.0 : 0.5;
            }
        }

        // Weighted combination: Capabilities > Embeddings > Drift
        return 0.5 * capScore + 0.3 * embeddingSim + 0.2 * driftScore;
    }

    /**
     * Check if action is explicitly denied
     */
    private isExplicitlyDenied(action: Action): boolean {
        return this.policy.globalRules.some(rule =>
            action.capabilities.some(cap => rule.deny?.includes(cap))
        );
    }

    /**
     * Get the deny rule for an action
     */
    private getDenyRule(action: Action): PolicyRule | undefined {
        return this.policy.globalRules.find(rule =>
            action.capabilities.some(cap => rule.deny?.includes(cap))
        );
    }

    /**
     * Check if action requires user confirmation
     */
    private requiresConfirmation(action: Action): boolean {
        // High-risk capabilities always require confirmation
        const hasHighRisk = action.capabilities.some(cap =>
            HIGH_RISK_CAPABILITIES.has(cap)
        );
        if (hasHighRisk) {
            return true;
        }

        // Check if any rule explicitly requires confirmation
        return this.policy.globalRules.some(rule =>
            rule.requireConfirmation &&
            action.capabilities.some(cap => rule.allow?.includes(cap))
        );
    }
}

/**
 * Authorization error
 */
export class AuthorizationError extends Error {
    constructor(message: string, public decision: AuthDecision) {
        super(message);
        this.name = 'AuthorizationError';
    }
}
