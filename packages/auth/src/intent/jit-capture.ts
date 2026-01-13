/**
 * JIT Intent Capture - Prompts user for intent on first high-privilege operation
 */

import type { IntentScope, Action } from '../types/index.js';
import { analyzeIntent } from './analyzer.js';
import { HIGH_RISK_CAPABILITIES } from '../authorization/capabilities.js';

/**
 * Check if action triggers intent capture
 */
export function shouldCaptureIntent(
    action: Action,
    currentIntent: IntentScope | null
): boolean {
    // Already have intent
    if (currentIntent) {
        return false;
    }

    // Check if action has high-risk capabilities
    const hasHighRisk = action.capabilities.some(cap =>
        HIGH_RISK_CAPABILITIES.has(cap)
    );

    return hasHighRisk;
}

/**
 * Capture user intent (JIT)
 * In real implementation, this would show a UI prompt
 */
export async function captureIntent(
    action: Action,
    promptUser: (message: string) => Promise<string>
): Promise<IntentScope> {
    // Prompt user for their intent
    const message = `
⚠️  HIGH-PRIVILEGE OPERATION DETECTED

The agent wants to: ${action.description}
Required capabilities: ${action.capabilities.join(', ')}

Please describe what you're trying to accomplish:
`.trim();

    try {
        const userResponse = await promptUser(message);

        if (!userResponse || userResponse.trim().length === 0) {
            // User declined or gave empty response - create restrictive intent
            return {
                originalPrompt: 'User declined to provide intent',
                primaryGoal: 'Unspecified',
                requiredCapabilities: [],
                scopeRestrictions: {},
                intentEmbedding: [],
                restrictive: true,
                capturedAt: Date.now(),
            };
        }

        // Analyze the user's response
        return analyzeIntent(userResponse);
    } catch (error) {
        // Error in prompting - fail secure with restrictive intent
        console.error('Failed to capture intent:', error);
        return {
            originalPrompt: 'Intent capture failed',
            primaryGoal: 'Error',
            requiredCapabilities: [],
            scopeRestrictions: {},
            intentEmbedding: [],
            restrictive: true,
            capturedAt: Date.now(),
        };
    }
}

/**
 * Create a mock prompt function for testing
 */
export function createMockPrompt(response: string): (message: string) => Promise<string> {
    return async (_message: string) => response;
}
