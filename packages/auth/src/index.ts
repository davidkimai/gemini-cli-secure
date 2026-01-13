/**
 * @gemini-cli/auth - Security authorization layer with adversarial control
 * Public API exports
 */

// Authorization
export { Capability, HIGH_RISK_CAPABILITIES, TOOL_CAPABILITIES, getToolCapabilities, isHighRisk, getCapabilitiesByCategory } from './authorization/capabilities.js';
export { AuthorizationEngine, AuthorizationError } from './authorization/engine.js';
export { loadPolicy, getDefaultPolicy } from './authorization/policy-loader.js';
export { generateAuthToken, verifyAuthToken, TokenVerificationError, type AuthToken } from './authorization/token-binding.js';

// Intent
export { analyzeIntent, extractCapabilities, extractScope, checkActionAlignment } from './intent/analyzer.js';
export { captureIntent, shouldCaptureIntent, createMockPrompt } from './intent/jit-capture.js';

// Audit
export { AuditLogger, createAuditLogger, type AuditEntry } from './audit/logger.js';

// Types
export type {
    Action,
    AuthDecision,
    AuthDecisionType,
    IntentScope,
    MonitorAssessment,
    SessionContext,
    PermissionPolicy,
    PolicyRule,
} from './types/index.js';
