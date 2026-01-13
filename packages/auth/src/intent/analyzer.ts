/**
 * Intent Analyzer - Extracts and validates user intent
 */

import type { IntentScope, Action } from '../types/index.js';
import { Capability } from '../authorization/capabilities.js';

/**
 * Extract required capabilities from user prompt
 * Simplified version for MVP - uses heuristics
 */
export function extractCapabilities(prompt: string): Capability[] {
    const caps: Capability[] = [];
    const lower = prompt.toLowerCase();

    // Filesystem operations
    if (lower.match(/\b(read|view|show|display|cat|open)\b.*\bfile/)) {
        caps.push(Capability.FILESYSTEM_READ);
    }
    if (lower.match(/\b(write|create|save|update|modify|edit)\b.*\bfile/)) {
        caps.push(Capability.FILESYSTEM_WRITE);
    }
    if (lower.match(/\b(delete|remove|rm)\b.*\bfile/)) {
        caps.push(Capability.FILESYSTEM_DELETE);
    }
    if (lower.match(/\b(list|ls|dir)\b/)) {
        caps.push(Capability.FILESYSTEM_LIST);
    }

    // Execution operations
    if (lower.match(/\b(run|execute|shell|command|script)\b/)) {
        caps.push(Capability.EXECUTION_SHELL);
    }

    // Network operations
    if (lower.match(/\b(fetch|download|get|curl|wget)\b.*\b(url|http|https)/)) {
        caps.push(Capability.NETWORK_HTTP_FETCH);
    }
    if (lower.match(/\b(search|google|query)\b/)) {
        caps.push(Capability.NETWORK_SEARCH);
    }

    // Default to read if no specific capability detected
    if (caps.length === 0) {
        caps.push(Capability.FILESYSTEM_READ);
    }

    return caps;
}

/**
 * Extract scope restrictions from prompt
 */
export function extractScope(prompt: string): {
    filesystemPaths?: string[];
    networkDomains?: string[];
} {
    const scope: {
        filesystemPaths?: string[];
        networkDomains?: string[];
    } = {};

    // Extract file paths (simple heuristic)
    const pathMatches = prompt.match(/[~/][\w\-./]+/g);
    if (pathMatches && pathMatches.length > 0) {
        scope.filesystemPaths = pathMatches.map(p => {
            // Expand to wildcard if specific file mentioned
            if (p.includes('/')) {
                const dir = p.substring(0, p.lastIndexOf('/'));
                return dir + '/*';
            }
            return p + '/*';
        });
    }

    // Extract domains (simple heuristic)
    const urlMatches = prompt.match(/https?:\/\/([^\/\s]+)/g);
    if (urlMatches && urlMatches.length > 0) {
        scope.networkDomains = urlMatches.map(url => {
            try {
                const domain = new URL(url).hostname;
                return domain;
            } catch {
                return url;
            }
        });
    }

    return scope;
}

/**
 * Analyze user prompt and create intent scope
 */
export function analyzeIntent(
    prompt: string,
    conversationHistory?: string[]
): IntentScope {
    const capabilities = extractCapabilities(prompt);
    const scope = extractScope(prompt);

    // Extract primary goal (first sentence or first 100 chars)
    let primaryGoal = prompt.split('.')[0];
    if (primaryGoal.length > 100) {
        primaryGoal = primaryGoal.substring(0, 100) + '...';
    }

    return {
        originalPrompt: prompt,
        primaryGoal,
        requiredCapabilities: capabilities,
        scopeRestrictions: scope,
        intentEmbedding: [], // TODO: Implement actual embeddings
        restrictive: false,
        capturedAt: Date.now(),
    };
}

/**
 * Check if action aligns with intent (simplified version)
 */
export function checkActionAlignment(
    action: Action,
    intent: IntentScope
): boolean {
    // Check if action capabilities are subset of intent capabilities
    const intentCaps = new Set(intent.requiredCapabilities);
    return action.capabilities.every(cap => intentCaps.has(cap));
}
