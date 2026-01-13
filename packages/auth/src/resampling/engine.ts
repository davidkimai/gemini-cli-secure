/**
 * Best-of-N Resampling Engine
 * Implements resampling protocol from spec.md Section 7
 */

import type { Action } from '../types/index.js';
import { Capability } from '../authorization/capabilities.js';

/**
 * Resampling configuration
 */
export interface ResamplingConfig {
    n: number; // Number of samples (default: 3)
    rankingStrategy: 'risk' | 'capability' | 'combined';
    enabledForCapabilities: Capability[];
}

/**
 * Ranked action with score
 */
export interface RankedAction {
    action: Action;
    score: number;
    rank: number;
}

/**
 * Resampling engine
 */
export class ResamplingEngine {
    constructor(private config: ResamplingConfig) { }

    /**
     * Check if action should trigger resampling
     */
    shouldResample(action: Action): boolean {
        return action.capabilities.some(cap =>
            this.config.enabledForCapabilities.includes(cap)
        );
    }

    /**
     * Rank actions using configured strategy
     */
    rankActions(actions: Action[]): RankedAction[] {
        const scored = actions.map(action => ({
            action,
            score: this.scoreAction(action),
            rank: 0,
        }));

        // Sort by score (lower is safer)
        scored.sort((a, b) => a.score - b.score);

        // Assign ranks
        scored.forEach((item, index) => {
            item.rank = index + 1;
        });

        return scored;
    }

    /**
     * Score an action (lower is safer)
     */
    private scoreAction(action: Action): number {
        switch (this.config.rankingStrategy) {
            case 'risk':
                return action.riskScore || 0.5;

            case 'capability':
                return this.scoreByCapability(action);

            case 'combined':
                const riskScore = action.riskScore || 0.5;
                const capScore = this.scoreByCapability(action);
                return (riskScore * 0.6) + (capScore * 0.4);

            default:
                return action.riskScore || 0.5;
        }
    }

    /**
     * Score action by capabilities (more dangerous caps = higher score)
     */
    private scoreByCapability(action: Action): number {
        const capabilityWeights: Record<string, number> = {
            [Capability.SYSTEM_PRIVILEGE_ESCALATE]: 1.0,
            [Capability.EXECUTION_SHELL]: 0.9,
            [Capability.FILESYSTEM_DELETE]: 0.8,
            [Capability.FILESYSTEM_WRITE]: 0.6,
            [Capability.NETWORK_HTTP_FETCH]: 0.5,
            [Capability.FILESYSTEM_READ]: 0.3,
            [Capability.NETWORK_SEARCH]: 0.2,
        };

        if (action.capabilities.length === 0) return 0.1;

        const totalWeight = action.capabilities.reduce((sum, cap) => {
            return sum + (capabilityWeights[cap] || 0.4);
        }, 0);

        return totalWeight / action.capabilities.length;
    }

    /**
     * Select best action from resampled candidates
     */
    selectBest(actions: Action[]): Action {
        const ranked = this.rankActions(actions);
        return ranked[0].action; // Return lowest-scored (safest) action
    }

    /**
     * Get resampling stats
     */
    getStats(actions: Action[]): {
        originalRisk: number;
        selectedRisk: number;
        riskReduction: number;
        alternatives: number;
    } {
        if (actions.length === 0) {
            return {
                originalRisk: 0,
                selectedRisk: 0,
                riskReduction: 0,
                alternatives: 0,
            };
        }

        const ranked = this.rankActions(actions);
        const originalRisk = actions[0].riskScore || 0.5;
        const selectedRisk = ranked[0].score;
        const riskReduction = originalRisk - selectedRisk;

        return {
            originalRisk,
            selectedRisk,
            riskReduction,
            alternatives: actions.length - 1,
        };
    }
}

/**
 * Create default resampling config
 */
export function createDefaultResamplingConfig(): ResamplingConfig {
    return {
        n: 3,
        rankingStrategy: 'combined',
        enabledForCapabilities: [
            Capability.EXECUTION_SHELL,
            Capability.SYSTEM_PRIVILEGE_ESCALATE,
            Capability.FILESYSTEM_DELETE,
            Capability.FILESYSTEM_WRITE,
        ],
    };
}

/**
 * Create resampling engine with default config
 */
export function createResamplingEngine(
    config?: Partial<ResamplingConfig>
): ResamplingEngine {
    const defaultConfig = createDefaultResamplingConfig();
    return new ResamplingEngine({ ...defaultConfig, ...config });
}
