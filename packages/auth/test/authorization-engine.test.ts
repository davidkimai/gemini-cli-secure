/**
 * Test suite for Authorization Engine
 * Validates capability checking, scope enforcement, and intent alignment
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { AuthorizationEngine } from '../src/authorization/engine.js';
import { Capability } from '../src/authorization/capabilities.js';
import { Action, IntentScope, PermissionPolicy } from '../src/types/index.js';

describe('Authorization Engine - F1 Capability-Based Authorization', () => {
    let policy: PermissionPolicy;
    let engine: AuthorizationEngine;

    beforeEach(() => {
        // Create test policy
        policy = {
            version: '1.0',
            defaultPolicy: {
                allow: [Capability.FILESYSTEM_READ, Capability.NETWORK_SEARCH],
                deny: [Capability.EXECUTION_SHELL, Capability.SYSTEM_PRIVILEGE_ESCALATE],
            },
            globalRules: [
                {
                    name: 'workspace_reads',
                    allow: [Capability.FILESYSTEM_READ],
                    scope: {
                        filesystemPaths: ['~/workspace/*', './project/*'],
                        exclude: ['*.env', '~/.ssh/*'],
                    },
                },
                {
                    name: 'controlled_writes',
                    allow: [Capability.FILESYSTEM_WRITE],
                    scope: {
                        filesystemPaths: ['~/workspace/outputs/*'],
                    },
                    requireConfirmation: true,
                },
                {
                    name: 'deny_privilege_escalate',
                    deny: [Capability.SYSTEM_PRIVILEGE_ESCALATE],
                    reason: 'Privilege escalation disabled',
                },
            ],
        };

        engine = new AuthorizationEngine(policy);
    });

    const createAction = (
        toolName: string,
        capabilities: Capability[],
        target: string
    ): Action => ({
        toolName,
        toolArgs: { path: target },
        description: `Test action ${toolName}`,
        capabilities,
        target,
        riskScore: 0.3,
        timestamp: Date.now(),
    });

    describe('Capability Checking', () => {
        it('should allow action with permitted capability', async () => {
            const action = createAction(
                'read_file',
                [Capability.FILESYSTEM_READ],
                '~/workspace/test.txt'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('allow');
            expect(decision.authToken).toBeDefined();
        });

        it('should deny action with forbidden capability', async () => {
            const action = createAction(
                'run_shell_command',
                [Capability.EXECUTION_SHELL],
                'ls -la'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('deny');
            expect(decision.reason).toContain('not permitted');
        });

        it('should deny action violating default policy', async () => {
            const action = createAction(
                'sudo_command',
                [Capability.SYSTEM_PRIVILEGE_ESCALATE],
                'sudo rm -rf /'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('deny');
        });

        it('should check all capabilities in multi-capability action', async () => {
            const action = createAction(
                'complex_operation',
                [Capability.FILESYSTEM_READ, Capability.EXECUTION_SHELL],
                '/tmp/script.sh'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('deny'); // Shell execution denied
        });
    });

    describe('Scope Enforcement', () => {
        it('should allow filesystem operation within scope', async () => {
            const action = createAction(
                'read_file',
                [Capability.FILESYSTEM_READ],
                '~/workspace/data.json'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('allow');
        });

        it('should deny filesystem operation outside scope', async () => {
            const action = createAction(
                'read_file',
                [Capability.FILESYSTEM_READ],
                '/etc/passwd'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('deny');
            expect(decision.reason).toContain('Out of scope');
        });

        it('should block excluded paths', async () => {
            const action = createAction(
                'read_file',
                [Capability.FILESYSTEM_READ],
                '~/workspace/secrets.env'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('deny');
        });

        it('should block SSH directory access', async () => {
            const action = createAction(
                'read_file',
                [Capability.FILESYSTEM_READ],
                '~/.ssh/id_rsa'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('deny');
        });

        it('should support wildcard patterns', async () => {
            const action = createAction(
                'read_file',
                [Capability.FILESYSTEM_READ],
                '~/workspace/subdir/file.txt'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('allow');
        });
    });

    describe('Confirmation Requirements', () => {
        it('should require confirmation for high-risk capabilities', async () => {
            // Temporarily allow shell for testing confirmation
            const testPolicy = {
                ...policy,
                defaultPolicy: {
                    allow: [Capability.EXECUTION_SHELL],
                    deny: [],
                },
                globalRules: [],
            };
            const testEngine = new AuthorizationEngine(testPolicy);

            const action = createAction(
                'run_shell_command',
                [Capability.EXECUTION_SHELL],
                'rm test.txt'
            );

            const decision = await testEngine.authorize(action, null);
            expect(decision.type).toBe('confirm'); // High-risk requires confirmation
        });

        it('should require confirmation when policy specifies', async () => {
            const action = createAction(
                'write_file',
                [Capability.FILESYSTEM_WRITE],
                '~/workspace/outputs/result.txt'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('confirm');
            expect(decision.reason).toContain('confirmation');
        });
    });

    describe('Explicit Deny Rules', () => {
        it('should deny based on explicit deny rule', async () => {
            const action = createAction(
                'sudo_command',
                [Capability.SYSTEM_PRIVILEGE_ESCALATE],
                'sudo apt-get install malware'
            );

            const decision = await engine.authorize(action, null);
            expect(decision.type).toBe('deny');
            expect(decision.reason).toContain('Privilege escalation disabled');
        });
    });

    describe('Intent Alignment', () => {
        const createIntent = (
            goal: string,
            capabilities: Capability[],
            paths: string[]
        ): IntentScope => ({
            originalPrompt: 'User prompt',
            primaryGoal: goal,
            requiredCapabilities: capabilities,
            scopeRestrictions: {
                filesystemPaths: paths,
            },
            intentEmbedding: [0.1, 0.2, 0.3],
            restrictive: false,
            capturedAt: Date.now(),
        });

        it('should allow action aligned with intent', async () => {
            const intent = createIntent(
                'Read workspace files',
                [Capability.FILESYSTEM_READ],
                ['~/workspace/*']
            );

            const action = createAction(
                'read_file',
                [Capability.FILESYSTEM_READ],
                '~/workspace/test.txt'
            );

            const decision = await engine.authorize(action, intent);
            expect(decision.type).toBe('allow');
            expect(decision.alignmentScore).toBeGreaterThan(0.8);
        });

        it('should deny action with high-risk capability mismatch', async () => {
            const intent = createIntent(
                'Read logs',
                [Capability.FILESYSTEM_READ],
                ['~/logs/*']
            );

            const action = createAction(
                'delete_file',
                [Capability.FILESYSTEM_DELETE],
                '~/logs/old.log'
            );

            const decision = await engine.authorize(action, intent);
            expect(decision.type).toBe('deny');
            expect(decision.alignmentScore).toBe(0.0); // Hard deny
        });

        it('should request confirmation for uncertain alignment', async () => {
            const intent = createIntent(
                'Analyze data',
                [Capability.FILESYSTEM_READ],
                ['~/data/*']
            );

            // Action has unexpected capability but not high-risk
            const action = createAction(
                'search',
                [Capability.NETWORK_SEARCH],
                'research query'
            );

            const decision = await engine.authorize(action, intent);
            // May be confirm due to capability mismatch
            expect(['confirm', 'allow']).toContain(decision.type);
        });
    });

    describe('Performance', () => {
        it('should authorize in <50ms per spec.md', async () => {
            const action = createAction(
                'read_file',
                [Capability.FILESYSTEM_READ],
                '~/workspace/test.txt'
            );

            const start = performance.now();
            await engine.authorize(action, null);
            const end = performance.now();

            expect(end - start).toBeLessThan(50);
        });

        it('should handle 100 sequential authorizations quickly', async () => {
            const actions = Array.from({ length: 100 }, (_, i) =>
                createAction(
                    'read_file',
                    [Capability.FILESYSTEM_READ],
                    `~/workspace/file${i}.txt`
                )
            );

            const start = performance.now();
            for (const action of actions) {
                await engine.authorize(action, null);
            }
            const end = performance.now();

            const avgTime = (end - start) / 100;
            expect(avgTime).toBeLessThan(50); // Average <50ms
        });
    });

    describe('Edge Cases', () => {
        it('should handle null intent gracefully', async () => {
            const action = createAction(
                'read_file',
                [Capability.FILESYSTEM_READ],
                '~/workspace/test.txt'
            );

            const decision = await engine.authorize(action, null);
            expect(decision).toBeDefined();
            expect(decision.type).toBeDefined();
        });

        it('should handle empty capabilities array', async () => {
            const action = createAction('no_op', [], '');

            const decision = await engine.authorize(action, null);
            expect(decision).toBeDefined();
        });

        it('should handle restrictive intent', async () => {
            const restrictiveIntent: IntentScope = {
                originalPrompt: 'Declined',
                primaryGoal: 'Unspecified',
                requiredCapabilities: [Capability.FILESYSTEM_READ],
                scopeRestrictions: {
                    filesystemPaths: ['~/workspace/*'],
                },
                intentEmbedding: [],
                restrictive: true,
                capturedAt: Date.now(),
            };

            const action = createAction(
                'read_file',
                [Capability.FILESYSTEM_READ],
                '~/workspace/test.txt'
            );

            const decision = await engine.authorize(action, restrictiveIntent);
            expect(decision.type).toBeDefined();
        });
    });
});
