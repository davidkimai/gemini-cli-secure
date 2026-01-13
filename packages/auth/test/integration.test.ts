/**
 * Integration tests for Day 2 components
 * Tests intent analyzer, JIT capture, and audit logger
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { analyzeIntent, extractCapabilities, extractScope } from '../src/intent/analyzer.js';
import { captureIntent, shouldCaptureIntent, createMockPrompt } from '../src/intent/jit-capture.js';
import { AuditLogger, createAuditLogger } from '../src/audit/logger.js';
import { Capability } from '../src/authorization/capabilities.js';
import type { Action, AuthDecision } from '../src/types/index.js';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('Intent Analyzer', () => {
    describe('Capability Extraction', () => {
        it('should extract read capability from prompt', () => {
            const prompt = 'Read the file test.txt';
            const caps = extractCapabilities(prompt);

            expect(caps).toContain(Capability.FILESYSTEM_READ);
        });

        it('should extract write capability from prompt', () => {
            const prompt = 'Create a new file called output.json';
            const caps = extractCapabilities(prompt);

            expect(caps).toContain(Capability.FILESYSTEM_WRITE);
        });

        it('should extract shell execution from prompt', () => {
            const prompt = 'Run the build script';
            const caps = extractCapabilities(prompt);

            expect(caps).toContain(Capability.EXECUTION_SHELL);
        });

        it('should extract network search capability', () => {
            const prompt = 'Search for documentation on React hooks';
            const caps = extractCapabilities(prompt);

            expect(caps).toContain(Capability.NETWORK_SEARCH);
        });

        it('should default to read if ambiguous', () => {
            const prompt = 'Help me with this project';
            const caps = extractCapabilities(prompt);

            expect(caps).toContain(Capability.FILESYSTEM_READ);
        });
    });

    describe('Scope Extraction', () => {
        it('should extract file paths from prompt', () => {
            const prompt = 'Read files in ~/workspace/data';
            const scope = extractScope(prompt);

            expect(scope.filesystemPaths).toBeDefined();
            expect(scope.filesystemPaths?.some(p => p.includes('workspace'))).toBe(true);
        });

        it('should extract domain from URL', () => {
            const prompt = 'Fetch data from https://api.example.com/data';
            const scope = extractScope(prompt);

            expect(scope.networkDomains).toBeDefined();
            expect(scope.networkDomains).toContain('api.example.com');
        });

        it('should handle prompts with no paths', () => {
            const prompt = 'Help me debug this code';
            const scope = extractScope(prompt);

            expect(scope.filesystemPaths).toBeUndefined();
            expect(scope.networkDomains).toBeUndefined();
        });
    });

    describe('Intent Analysis', () => {
        it('should create complete intent scope', () => {
            const prompt = 'Read logs from ~/app/logs and search for errors';
            const intent = analyzeIntent(prompt);

            expect(intent.originalPrompt).toBe(prompt);
            expect(intent.primaryGoal).toBeDefined();
            expect(intent.requiredCapabilities.length).toBeGreaterThan(0);
            expect(intent.restrictive).toBe(false);
            expect(intent.capturedAt).toBeGreaterThan(0);
        });

        it('should extract primary goal', () => {
            const prompt = 'Analyze the database schema. Then create documentation.';
            const intent = analyzeIntent(prompt);

            expect(intent.primaryGoal).toBe('Analyze the database schema');
        });

        it('should truncate long primary goals', () => {
            const longPrompt = 'A'.repeat(150);
            const intent = analyzeIntent(longPrompt);

            expect(intent.primaryGoal.length).toBeLessThanOrEqual(104); // 100 + '...'
        });
    });
});

describe('JIT Intent Capture', () => {
    const createTestAction = (capabilities: Capability[]): Action => ({
        toolName: 'test_tool',
        toolArgs: {},
        description: 'Test action',
        capabilities,
        target: '/test',
        riskScore: 0.5,
        timestamp: Date.now(),
    });

    describe('Trigger Detection', () => {
        it('should trigger on high-risk capability', () => {
            const action = createTestAction([Capability.EXECUTION_SHELL]);
            const should = shouldCaptureIntent(action, null);

            expect(should).toBe(true);
        });

        it('should not trigger if intent already exists', () => {
            const action = createTestAction([Capability.EXECUTION_SHELL]);
            const existingIntent = analyzeIntent('Test intent');
            const should = shouldCaptureIntent(action, existingIntent);

            expect(should).toBe(false);
        });

        it('should not trigger on low-risk operations', () => {
            const action = createTestAction([Capability.FILESYSTEM_READ]);
            const should = shouldCaptureIntent(action, null);

            expect(should).toBe(false);
        });
    });

    describe('Intent Capture', () => {
        it('should capture intent from user response', async () => {
            const action = createTestAction([Capability.EXECUTION_SHELL]);
            const mockPrompt = createMockPrompt('I want to build the project');

            const intent = await captureIntent(action, mockPrompt);

            expect(intent.restrictive).toBe(false);
            expect(intent.originalPrompt).toBe('I want to build the project');
            expect(intent.primaryGoal).toBeDefined();
        });

        it('should create restrictive intent on empty response', async () => {
            const action = createTestAction([Capability.EXECUTION_SHELL]);
            const mockPrompt = createMockPrompt('');

            const intent = await captureIntent(action, mockPrompt);

            expect(intent.restrictive).toBe(true);
            expect(intent.requiredCapabilities).toEqual([]);
        });

        it('should create restrictive intent on error', async () => {
            const action = createTestAction([Capability.EXECUTION_SHELL]);
            const failingPrompt = async () => {
                throw new Error('Prompt failed');
            };

            const intent = await captureIntent(action, failingPrompt);

            expect(intent.restrictive).toBe(true);
            expect(intent.primaryGoal).toBe('Error');
        });
    });
});

describe('Audit Logger', () => {
    let tempDir: string;
    let logPath: string;
    let logger: AuditLogger;

    beforeEach(() => {
        tempDir = mkdtempSync(join(tmpdir(), 'audit-test-'));
        logPath = join(tempDir, 'test-audit.log');
        logger = createAuditLogger(logPath);
    });

    afterEach(() => {
        rmSync(tempDir, { recursive: true, force: true });
    });

    const createTestAction = (): Action => ({
        toolName: 'read_file',
        toolArgs: { path: '/test.txt' },
        description: 'Read test file',
        capabilities: [Capability.FILESYSTEM_READ],
        target: '/test.txt',
        riskScore: 0.2,
        timestamp: Date.now(),
    });

    const createTestDecision = (action: Action): AuthDecision => ({
        type: 'allow',
        action,
        authToken: 'test-token',
        timestamp: Date.now(),
    });

    describe('Basic Logging', () => {
        it('should log authorization decision', () => {
            const action = createTestAction();
            const decision = createTestDecision(action);

            expect(() => {
                logger.log(action, decision, 'user1', 'session1');
            }).not.toThrow();
        });

        it('should log security events', () => {
            expect(() => {
                logger.logSecurityEvent(
                    'UNAUTHORIZED_ACCESS',
                    { path: '/etc/passwd' },
                    'user1',
                    'session1'
                );
            }).not.toThrow();
        });
    });

    describe('Tamper-Evident Chain', () => {
        it('should generate hash chain', () => {
            const action1 = createTestAction();
            const decision1 = createTestDecision(action1);

            logger.log(action1, decision1);
            const hash1 = logger.getCurrentHash();

            const action2 = createTestAction();
            const decision2 = createTestDecision(action2);

            logger.log(action2, decision2);
            const hash2 = logger.getCurrentHash();

            expect(hash1).not.toBe(hash2);
            expect(hash1).toMatch(/^[a-f0-9]{64}$/);
            expect(hash2).toMatch(/^[a-f0-9]{64}$/);
        });

        it('should start with initial hash', () => {
            const initialHash = logger.getCurrentHash();
            expect(initialHash).toBe('0');
        });

        it('should update hash after each log', () => {
            const action = createTestAction();
            const decision = createTestDecision(action);

            const before = logger.getCurrentHash();
            logger.log(action, decision);
            const after = logger.getCurrentHash();

            expect(before).not.toBe(after);
        });
    });

    describe('Log File Creation', () => {
        it('should create log directory if not exists', () => {
            const nestedPath = join(tempDir, 'nested', 'dir', 'audit.log');
            const nestedLogger = createAuditLogger(nestedPath);

            const action = createTestAction();
            const decision = createTestDecision(action);

            expect(() => {
                nestedLogger.log(action, decision);
            }).not.toThrow();
        });
    });
});

describe('Integration Scenarios', () => {
    it('should complete full intent capture and authorization flow', async () => {
        // Step 1: User triggers high-risk operation
        const action: Action = {
            toolName: 'run_shell_command',
            toolArgs: { command: 'npm install' },
            description: 'Install dependencies',
            capabilities: [Capability.EXECUTION_SHELL],
            target: 'npm install',
            riskScore: 0.8,
            timestamp: Date.now(),
        };

        // Step 2: System detects missing intent
        expect(shouldCaptureIntent(action, null)).toBe(true);

        // Step 3: Capture intent from user
        const mockPrompt = createMockPrompt('I want to install project dependencies');
        const intent = await captureIntent(action, mockPrompt);


        expect(intent.restrictive).toBe(false);
        // Intent analyzer should extract shell capability from "install" keyword
        expect(intent.requiredCapabilities.length).toBeGreaterThan(0);

        // Step 4: Log the intent capture
        const tempDir = mkdtempSync(join(tmpdir(), 'integration-test-'));
        const logger = createAuditLogger(join(tempDir, 'audit.log'));

        logger.logSecurityEvent(
            'INTENT_CAPTURED',
            { intent: intent.primaryGoal },
            'test-user',
            'test-session'
        );

        expect(logger.getCurrentHash()).not.toBe('0');

        // Cleanup
        rmSync(tempDir, { recursive: true, force: true });
    });
});
