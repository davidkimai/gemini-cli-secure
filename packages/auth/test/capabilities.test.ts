/**
 * Test suite for Capability system
 */

import { describe, it, expect } from 'vitest';
import {
    Capability,
    HIGH_RISK_CAPABILITIES,
    TOOL_CAPABILITIES,
    getToolCapabilities,
    isHighRisk,
    getCapabilitiesByCategory,
} from '../src/authorization/capabilities.js';

describe('Capability Taxonomy', () => {
    it('should have all required capability categories', () => {
        const categories = ['filesystem', 'execution', 'network', 'system', 'data', 'ipc'];

        categories.forEach(category => {
            const caps = getCapabilitiesByCategory(category);
            expect(caps.length).toBeGreaterThan(0);
        });
    });

    it('should identify high-risk capabilities correctly', () => {
        expect(isHighRisk(Capability.SYSTEM_PRIVILEGE_ESCALATE)).toBe(true);
        expect(isHighRisk(Capability.EXECUTION_SHELL)).toBe(true);
        expect(isHighRisk(Capability.FILESYSTEM_DELETE)).toBe(true);
        expect(isHighRisk(Capability.FILESYSTEM_READ)).toBe(false);
        expect(isHighRisk(Capability.NETWORK_SEARCH)).toBe(false);
    });

    it('should have HIGH_RISK_CAPABILITIES set defined', () => {
        expect(HIGH_RISK_CAPABILITIES.size).toBeGreaterThan(0);
        expect(HIGH_RISK_CAPABILITIES.has(Capability.SYSTEM_PRIVILEGE_ESCALATE)).toBe(true);
    });

    describe('Tool-to-Capability Mapping', () => {
        it('should map read_file to FILESYSTEM_READ', () => {
            const caps = getToolCapabilities('read_file');
            expect(caps).toContain(Capability.FILESYSTEM_READ);
        });

        it('should map write_file to FILESYSTEM_WRITE', () => {
            const caps = getToolCapabilities('write_file');
            expect(caps).toContain(Capability.FILESYSTEM_WRITE);
        });

        it('should map run_shell_command to EXECUTION_SHELL', () => {
            const caps = getToolCapabilities('run_shell_command');
            expect(caps).toContain(Capability.EXECUTION_SHELL);
        });

        it('should map web_fetch to NETWORK_HTTP_FETCH', () => {
            const caps = getToolCapabilities('web_fetch');
            expect(caps).toContain(Capability.NETWORK_HTTP_FETCH);
        });

        it('should return empty array for unknown tool', () => {
            const caps = getToolCapabilities('unknown_tool');
            expect(caps).toEqual([]);
        });
    });

    describe('Filesystem Capabilities', () => {
        it('should include all filesystem operations', () => {
            const fsCaps = getCapabilitiesByCategory('filesystem');

            expect(fsCaps).toContain(Capability.FILESYSTEM_READ);
            expect(fsCaps).toContain(Capability.FILESYSTEM_WRITE);
            expect(fsCaps).toContain(Capability.FILESYSTEM_DELETE);
            expect(fsCaps).toContain(Capability.FILESYSTEM_LIST);
            expect(fsCaps).toContain(Capability.FILESYSTEM_SYMLINK);
        });
    });

    describe('Execution Capabilities', () => {
        it('should include shell execution', () => {
            const execCaps = getCapabilitiesByCategory('execution');

            expect(execCaps).toContain(Capability.EXECUTION_SHELL);
            expect(execCaps).toContain(Capability.EXECUTION_SUBPROCESS);
        });
    });

    describe('Network Capabilities', () => {
        it('should include network operations', () => {
            const netCaps = getCapabilitiesByCategory('network');

            expect(netCaps).toContain(Capability.NETWORK_HTTP_FETCH);
            expect(netCaps).toContain(Capability.NETWORK_SEARCH);
            expect(netCaps).toContain(Capability.NETWORK_TCP_CONNECT);
        });
    });
});
