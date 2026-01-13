/**
 * Audit Logger - Tamper-evident logging for security events
 */

import { createHash } from 'crypto';
import { appendFileSync, existsSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import type { Action, AuthDecision } from '../types/index.js';

/**
 * Audit log entry
 */
export interface AuditEntry {
    timestamp: number;
    action: Action;
    decision: AuthDecision;
    userId?: string;
    sessionId?: string;
    previousHash?: string;
    currentHash?: string;
}

/**
 * Audit Logger
 */
export class AuditLogger {
    private lastHash: string = '0';

    constructor(private logPath: string, private tamperEvident: boolean = true) {
        // Ensure log directory exists
        const dir = dirname(logPath);
        if (!existsSync(dir)) {
            mkdirSync(dir, { recursive: true });
        }
    }

    /**
     * Log an authorization decision
     */
    log(
        action: Action,
        decision: AuthDecision,
        userId?: string,
        sessionId?: string
    ): void {
        const entry: AuditEntry = {
            timestamp: Date.now(),
            action,
            decision,
            userId,
            sessionId,
        };

        if (this.tamperEvident) {
            // Add tamper-evident chain
            entry.previousHash = this.lastHash;
            entry.currentHash = this.computeHash(entry);
            this.lastHash = entry.currentHash;
        }

        // Write to log file
        try {
            const logLine = JSON.stringify(entry) + '\n';
            appendFileSync(this.logPath, logLine, 'utf8');
        } catch (error) {
            console.error('Failed to write audit log:', error);
        }
    }

    /**
     * Compute hash for tamper-evident chain
     */
    private computeHash(entry: Partial<AuditEntry>): string {
        const data = JSON.stringify({
            timestamp: entry.timestamp,
            action: entry.action,
            decision: entry.decision,
            previousHash: entry.previousHash,
        });

        return createHash('sha256').update(data).digest('hex');
    }

    /**
     * Log a security event
     */
    logSecurityEvent(
        eventType: string,
        details: Record<string, unknown>,
        userId?: string,
        sessionId?: string
    ): void {
        const fakeAction: Action = {
            toolName: 'security_event',
            toolArgs: details,
            description: eventType,
            capabilities: [],
            target: '',
            riskScore: 1.0,
            timestamp: Date.now(),
        };

        const fakeDecision: AuthDecision = {
            type: 'deny',
            action: fakeAction,
            reason: eventType,
            timestamp: Date.now(),
        };

        this.log(fakeAction, fakeDecision, userId, sessionId);
    }

    /**
     * Get current chain hash (for verification)
     */
    getCurrentHash(): string {
        return this.lastHash;
    }
}

/**
 * Create a default audit logger
 */
export function createAuditLogger(logPath: string): AuditLogger {
    return new AuditLogger(logPath, true);
}
