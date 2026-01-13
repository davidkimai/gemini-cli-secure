/**
 * Test suite for Cryptographic Token Binding (TOCTOU Prevention)
 */

import { describe, it, expect, beforeEach } from 'vitest';
import {
    generateAuthToken,
    verifyAuthToken,
    initializeSecretKey,
    TokenVerificationError,
} from '../src/authorization/token-binding.js';
import { Action } from '../src/types/index.js';
import { Capability } from '../src/authorization/capabilities.js';

describe('Cryptographic Token Binding - TOCTOU Prevention', () => {
    beforeEach(() => {
        // Initialize with a known secret for testing
        initializeSecretKey('test-secret-key-for-unit-tests-only');
    });

    const createTestAction = (): Action => ({
        toolName: 'read_file',
        toolArgs: { path: '/home/user/test.txt' },
        description: 'Read test file',
        capabilities: [Capability.FILESYSTEM_READ],
        target: '/home/user/test.txt',
        riskScore: 0.2,
        timestamp: Date.now(),
    });

    describe('Token Generation - F2 Acceptance Criteria', () => {
        it('should generate token with HMAC-SHA256 signature', () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);

            expect(tokenString).toBeDefined();
            const token = JSON.parse(tokenString);

            expect(token.signature).toBeDefined();
            expect(token.signature).toMatch(/^[a-f0-9]{64}$/); // SHA256 hex
        });

        it('should include expiration timestamp', () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);
            const token = JSON.parse(tokenString);

            expect(token.expires).toBeDefined();
            expect(token.expires).toBeGreaterThan(Date.now());
        });

        it('should have 60-second validity window', () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);
            const token = JSON.parse(tokenString);

            const now = Date.now();
            const expectedExpiry = now + 60000; // 60 seconds
            const tolerance = 1000; // 1 second tolerance

            expect(token.expires).toBeGreaterThanOrEqual(expectedExpiry - tolerance);
            expect(token.expires).toBeLessThanOrEqual(expectedExpiry + tolerance);
        });

        it('should generate unique nonce for each token', () => {
            const action = createTestAction();
            const token1 = JSON.parse(generateAuthToken(action));
            const token2 = JSON.parse(generateAuthToken(action));

            expect(token1.nonce).toBeDefined();
            expect(token2.nonce).toBeDefined();
            expect(token1.nonce).not.toBe(token2.nonce);
        });

        it('should include canonical representation of action', () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);
            const token = JSON.parse(tokenString);

            expect(token.canonical).toBeDefined();
            expect(token.canonical).toContain(action.toolName);
            expect(token.canonical).toContain(action.target);
        });
    });

    describe('Token Verification - TOCTOU Prevention', () => {
        it('should verify valid token for unmodified action', () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);

            const isValid = verifyAuthToken(tokenString, action);
            expect(isValid).toBe(true);
        });

        it('should reject token if tool name is modified', () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);

            // Modify tool name after authorization
            const modifiedAction = { ...action, toolName: 'write_file' };

            const isValid = verifyAuthToken(tokenString, modifiedAction);
            expect(isValid).toBe(false);
        });

        it('should reject token if tool args are modified', () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);

            // Modify args after authorization
            const modifiedAction = {
                ...action,
                toolArgs: { path: '/etc/passwd' }, // TOCTOU attack!
            };

            const isValid = verifyAuthToken(tokenString, modifiedAction);
            expect(isValid).toBe(false);
        });

        it('should reject token if target is modified', () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);

            // Modify target after authorization
            const modifiedAction = {
                ...action,
                target: '/etc/passwd',
            };

            const isValid = verifyAuthToken(tokenString, modifiedAction);
            expect(isValid).toBe(false);
        });

        it('should reject token if capabilities are modified', () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);

            // Add write capability after authorization
            const modifiedAction = {
                ...action,
                capabilities: [Capability.FILESYSTEM_READ, Capability.FILESYSTEM_WRITE],
            };

            const isValid = verifyAuthToken(tokenString, modifiedAction);
            expect(isValid).toBe(false);
        });

        it('should reject expired token', async () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);
            const token = JSON.parse(tokenString);

            // Manually expire the token
            token.expires = Date.now() - 1000; // 1 second ago
            const expiredTokenString = JSON.stringify(token);

            const isValid = verifyAuthToken(expiredTokenString, action);
            expect(isValid).toBe(false);
        });

        it('should reject token with invalid signature', () => {
            const action = createTestAction();
            const tokenString = generateAuthToken(action);
            const token = JSON.parse(tokenString);

            // Tamper with signature
            token.signature = 'invalid_signature_' + token.signature.slice(17);
            const tamperedTokenString = JSON.stringify(token);

            const isValid = verifyAuthToken(tamperedTokenString, action);
            expect(isValid).toBe(false);
        });

        it('should reject malformed token JSON', () => {
            const action = createTestAction();
            const malformedToken = '{ invalid json';

            const isValid = verifyAuthToken(malformedToken, action);
            expect(isValid).toBe(false);
        });
    });

    describe('TOCTOU Attack Scenarios', () => {
        it('should prevent file path substitution attack', () => {
            // Scenario: Authorize read of user file, attempt to read /etc/passwd
            const authorizedAction = createTestAction();
            const token = generateAuthToken(authorizedAction);

            const attackAction = {
                ...authorizedAction,
                toolArgs: { path: '/etc/passwd' },
                target: '/etc/passwd',
            };

            expect(verifyAuthToken(token, attackAction)).toBe(false);
        });

        it('should prevent tool substitution attack', () => {
            // Scenario: Authorize read_file, attempt to execute write_file
            const authorizedAction = createTestAction();
            const token = generateAuthToken(authorizedAction);

            const attackAction = {
                ...authorizedAction,
                toolName: 'write_file',
                capabilities: [Capability.FILESYSTEM_WRITE],
            };

            expect(verifyAuthToken(token, attackAction)).toBe(false);
        });

        it('should prevent capability escalation attack', () => {
            // Scenario: Authorize with READ, attempt to execute with WRITE
            const authorizedAction = createTestAction();
            const token = generateAuthToken(authorizedAction);

            const attackAction = {
                ...authorizedAction,
                capabilities: [
                    Capability.FILESYSTEM_READ,
                    Capability.FILESYSTEM_WRITE,
                    Capability.EXECUTION_SHELL,
                ],
            };

            expect(verifyAuthToken(token, attackAction)).toBe(false);
        });
    });

    describe('Performance', () => {
        it('should generate and verify token in <50ms', () => {
            const action = createTestAction();

            const start = performance.now();
            const token = generateAuthToken(action);
            const verified = verifyAuthToken(token, action);
            const end = performance.now();

            expect(verified).toBe(true);
            expect(end - start).toBeLessThan(50); // <50ms per spec.md
        });
    });
});
