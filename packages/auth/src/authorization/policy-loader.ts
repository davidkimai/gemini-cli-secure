/**
 * Policy loader - YAML configuration parsing
 */

import { readFileSync } from 'fs';
import yaml from 'js-yaml';
import { homedir } from 'os';
import { join } from 'path';
import type { PermissionPolicy, PolicyRule } from '../types/index.js';
import { Capability } from './capabilities.js';

/**
 * Default policy path
 */
const DEFAULT_POLICY_PATH = join(homedir(), '.gemini', 'permissions.yaml');

/**
 * Load permission policy from file
 */
export function loadPolicy(userId: string, policyPath?: string): PermissionPolicy {
    const path = policyPath || DEFAULT_POLICY_PATH;

    try {
        const content = readFileSync(path, 'utf8');
        const rawPolicy = yaml.load(content) as any;

        return parsePolicy(rawPolicy);
    } catch (error) {
        console.warn(`Failed to load policy from ${path}, using default:`, error);
        return getDefaultPolicy();
    }
}

/**
 * Parse raw YAML into typed Policy structure
 */
function parsePolicy(raw: any): PermissionPolicy {
    return {
        version: raw.version || '1.0',
        defaultPolicy: {
            allow: parseCapabilities(raw.default_policy?.allow),
            deny: parseCapabilities(raw.default_policy?.deny),
        },
        globalRules: parseRules(raw.global_rules || []),
        monitoring: raw.monitoring ? {
            enabled: raw.monitoring.enabled ?? false,
            trustedModel: raw.monitoring.trusted_model,
            untrustedModel: raw.monitoring.untrusted_model,
            suspicionThreshold: raw.monitoring.suspicion_threshold ?? 0.7,
            budgetPerUserMonthly: raw.monitoring.budget_per_user_monthly ?? 10.0,
        } : undefined,
        audit: raw.audit ? {
            logAllActions: raw.audit.log_all_actions ?? true,
            logPath: raw.audit.log_path || join(homedir(), '.gemini', 'audit.log'),
            tamperEvident: raw.audit.tamper_evident ?? true,
            remoteBackup: raw.audit.remote_backup ?? false,
        } : undefined,
        degradation: raw.degradation ? {
            failSecureHighRisk: raw.degradation.fail_secure_high_risk ?? true,
            failOpenLowRisk: raw.degradation.fail_open_low_risk ?? true,
            heuristicFallback: raw.degradation.heuristic_fallback ?? true,
        } : undefined,
    };
}

/**
 * Parse capability strings into Capability enum
 */
function parseCapabilities(caps: string[] | undefined): Capability[] | undefined {
    if (!caps) return undefined;

    return caps.map(cap => {
        // Convert from YAML format (e.g., "filesystem.read") to enum
        const enumKey = Object.entries(Capability).find(
            ([_, value]) => value === cap
        )?.[0];

        if (!enumKey) {
            console.warn(`Unknown capability: ${cap}`);
            return null;
        }

        return Capability[enumKey as keyof typeof Capability];
    }).filter((cap): cap is Capability => cap !== null);
}

/**
 * Parse policy rules
 */
function parseRules(rawRules: any[]): PolicyRule[] {
    return rawRules.map(rule => ({
        name: rule.name,
        allow: parseCapabilities(rule.allow),
        deny: parseCapabilities(rule.deny),
        scope: rule.scope ? {
            filesystemPaths: rule.scope.filesystem_paths,
            networkDomains: rule.scope.network_domains,
            exclude: rule.scope.exclude,
        } : undefined,
        requireConfirmation: rule.require_confirmation ?? false,
        reason: rule.reason,
    }));
}

/**
 * Get default safe policy
 */
export function getDefaultPolicy(): PermissionPolicy {
    return {
        version: '1.0',
        defaultPolicy: {
            allow: [
                Capability.FILESYSTEM_READ,
                Capability.FILESYSTEM_LIST,
                Capability.NETWORK_SEARCH,
            ],
            deny: [
                Capability.FILESYSTEM_WRITE,
                Capability.FILESYSTEM_DELETE,
                Capability.EXECUTION_SHELL,
                Capability.NETWORK_HTTP_FETCH,
                Capability.SYSTEM_PRIVILEGE_ESCALATE,
            ],
        },
        globalRules: [
            {
                name: 'workspace_reads',
                allow: [Capability.FILESYSTEM_READ, Capability.FILESYSTEM_LIST],
                scope: {
                    filesystemPaths: ['~/workspace/*', './project/*'],
                    exclude: ['*.env', '**/.env', '~/.ssh/**', '**/secrets/**', '**/*.key'],
                },
                requireConfirmation: false,
            },
            {
                name: 'deny_privilege_escalation',
                deny: [Capability.SYSTEM_PRIVILEGE_ESCALATE],
                reason: 'Privilege escalation disabled for security',
            },
        ],
        monitoring: {
            enabled: false,
            trustedModel: 'claude-sonnet-4.5',
            untrustedModel: 'llama-3-70b-groq',
            suspicionThreshold: 0.7,
            budgetPerUserMonthly: 10.0,
        },
        audit: {
            logAllActions: true,
            logPath: join(homedir(), '.gemini', 'audit.log'),
            tamperEvident: true,
            remoteBackup: false,
        },
        degradation: {
            failSecureHighRisk: true,
            failOpenLowRisk: true,
            heuristicFallback: true,
        },
    };
}
