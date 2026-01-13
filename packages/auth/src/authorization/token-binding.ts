/**
 * Cryptographic token binding for TOCTOU prevention
 * Ensures actions cannot be modified between authorization and execution
 */

import { createHmac, randomBytes } from 'crypto';
import type { Action } from '../types/index.js';

/**
 * Authorization token structure
 */
export interface AuthToken {
    /** Canonical representation of the authorized action */
    canonical: string;

    /** HMAC signature */
    signature: string;

    /** Expiration timestamp */
    expires: number;

    /** Unique nonce */
    nonce: string;
}

/**
 * Secret key for HMAC (should be loaded from secure storage)
 */
let secretKey: string | null = null;

/**
 * Initialize or load the secret key
 */
export function initializeSecretKey(key?: string): void {
    if (key) {
        secretKey = key;
    } else {
        // Generate a new secret key (in production, this should be persisted)
        secretKey = randomBytes(32).toString('hex');
    }
}

/**
 * Get the secret key (initialize if needed)
 */
function getSecretKey(): string {
    if (!secretKey) {
        initializeSecretKey();
    }
    return secretKey!;
}

/**
 * Generate cryptographic token binding authorization to exact action
 */
export function generateAuthToken(action: Action): string {
    const nonce = randomBytes(16).toString('hex');

    // Create canonical representation
    const canonical = JSON.stringify({
        tool: action.toolName,
        args: Object.entries(action.toolArgs).sort(([a], [b]) => a.localeCompare(b)),
        capabilities: [...action.capabilities].sort(),
        target: action.target,
        timestamp: action.timestamp,
        nonce: nonce,
    }, null, 0); // No whitespace for canonical form

    // Generate HMAC signature
    const hmac = createHmac('sha256', getSecretKey());
    hmac.update(canonical);
    const signature = hmac.digest('hex');

    // Token expires in 60 seconds
    const expires = Date.now() + 60000;

    const token: AuthToken = {
        canonical,
        signature,
        expires,
        nonce,
    };

    return JSON.stringify(token);
}

/**
 * Verify authorization token matches the action being executed
 */
export function verifyAuthToken(
    tokenString: string,
    action: Action
): boolean {
    try {
        const token: AuthToken = JSON.parse(tokenString);

        // Check expiration
        if (Date.now() > token.expires) {
            throw new Error('Authorization token expired');
        }

        // Reconstruct canonical form from current action
        const canonical = JSON.stringify({
            tool: action.toolName,
            args: Object.entries(action.toolArgs).sort(([a], [b]) => a.localeCompare(b)),
            capabilities: [...action.capabilities].sort(),
            target: action.target,
            timestamp: action.timestamp,
            nonce: token.nonce,
        }, null, 0);

        // Verify canonical matches
        if (canonical !== token.canonical) {
            throw new Error('Action modified after authorization');
        }

        // Verify signature
        const hmac = createHmac('sha256', getSecretKey());
        hmac.update(canonical);
        const expectedSignature = hmac.digest('hex');

        if (expectedSignature !== token.signature) {
            throw new Error('Invalid token signature');
        }

        return true;
    } catch (error) {
        console.error('Token verification failed:', error);
        return false;
    }
}

/**
 * Security error for token verification failures
 */
export class TokenVerificationError extends Error {
    constructor(message: string) {
        super(message);
        this.name = 'TokenVerificationError';
    }
}
