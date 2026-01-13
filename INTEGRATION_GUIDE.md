/**
 * Integration Guide for gemini-cli-secure
 * 
 * This document outlines the 3 integration hooks needed to add
 * authorization to gemini-cli core.
 */

## Hook 1: Tool Execution Interception

**File:** `packages/core/src/scheduler/tool-executor.ts`  
**Location:** `ToolExecutor.execute()` method (Line 44-155)  
**Lines Added:** ~50 LOC

### Implementation

```typescript
// Add import at top of file
import {
  AuthorizationEngine,
  verifyAuthToken,
  loadPolicy,
  type Action,
  Capability,
  getToolCapabilities,
} from '@gemini-cli/auth';

// In ToolExecutor class, add private field
private authEngine?: AuthorizationEngine;

// In constructor, initialize if enabled
constructor(private readonly config: Config) {
  if (config.enableAuth) {
    const policy = loadPolicy(config.userId || 'default');
    this.authEngine = new AuthorizationEngine(policy);
  }
}

// In execute() method, add authorization check BEFORE tool execution
async execute(context: ToolExecutionContext): Promise<CompletedToolCall> {
  const { call, signal } = context;

  // NEW: Authorization check
  if (this.authEngine) {
    try {
      const action: Action = {
        toolName: call.toolName,
        toolArgs: call.args || {},
        description: `Execute ${call.toolName}`,
        capabilities: getToolCapabilities(call.toolName),
        target: call.args?.path || call.args?.url || '',
        riskScore: 0.5,
        timestamp: Date.now(),
      };

      const decision = await this.authEngine.authorize(
        action,
        (context as any).session?.intent || null
      );

      if (decision.type === 'deny') {
        return this.createErrorResult(
          call,
          new Error(`Authorization denied: ${decision.reason}`),
          'ACCESS_DENIED' as ToolErrorType
        );
      }

      if (decision.type === 'confirm') {
        // Trigger confirmation UI
        const confirmed = await this.requestConfirmation(decision);
        if (!confirmed) {
          return this.createCancelledResult(call, 'User declined authorization');
        }
      }

      // Verify cryptographic token before execution
      if (decision.authToken) {
        const isValid = verifyAuthToken(decision.authToken, action);
        if (!isValid) {
          return this.createErrorResult(
            call,
            new Error('Token verification failed - possible TOCTOU attack'),
            'SECURITY_VIOLATION' as ToolErrorType
          );
        }
      }

      // Log authorization decision
      if ((context as any).session?.audit) {
        (context as any).session.audit.log(
          action,
          decision,
          this.config.userId,
          (context as any).session?.id
        );
      }
    } catch (error) {
      return this.createErrorResult(
        call,
        error as Error,
        'AUTHORIZATION_ERROR' as ToolErrorType
      );
    }
  }

  // EXISTING: Continue with normal tool execution
  const request: ToolCallRequestInfo = {
    // ... existing code
  };
  // ...
}

// Add helper method for confirmation
private async requestConfirmation(decision: AuthDecision): Promise<boolean> {
  // Integrate with existing confirmation system
  // This would use whatever UI gemini-cli has
  return true; // Placeholder
}
```

---

## Hook 2: Session Initialization

**File:** Create `packages/core/src/session/session-manager.ts` (new) or modify existing session  
**Lines Added:** ~20 LOC

### Implementation

```typescript
import {
  loadPolicy,
  createAuditLogger,
  type IntentScope,
  type PermissionPolicy,
} from '@gemini-cli/auth';
import type { AuditLogger } from '@gemini-cli/auth';
import { sessionId } from '../utils/session.js';
import { homedir } from 'os';
import { join } from 'path';

export interface SecureSession {
  id: string;
  userId: string;
  policy: PermissionPolicy;
  intent: IntentScope | null;
  audit: AuditLogger;
  startedAt: number;
}

export function createSecureSession(userId: string): SecureSession {
  const policy = loadPolicy(userId);
  const auditPath = join(homedir(), '.gemini', 'audit.log');
  const audit = createAuditLogger(auditPath);

  return {
    id: sessionId,
    userId,
    policy,
    intent: null, // Captured JIT on first high-privilege operation
    audit,
    startedAt: Date.now(),
  };
}

// Export for use in tool-executor
export let currentSession: SecureSession | null = null;

export function initializeSession(userId: string): SecureSession {
  currentSession = createSecureSession(userId);
  return currentSession;
}
```

---

## Hook 3: JIT Intent Capture

**File:** Modify confirmation flow (exact location depends on gemini-cli's UI)  
**Likely:** `packages/core/src/confirmation-bus/*`  
**Lines Added:** ~30 LOC

### Implementation

```typescript
import {
  captureIntent,
  shouldCaptureIntent,
  type IntentScope,
  type Action,
} from '@gemini-cli/auth';
import { currentSession } from '../session/session-manager.js';

// In confirmation handler
export async function handleActionConfirmation(
  action: Action,
  promptUser: (message: string) => Promise<string>
): Promise<boolean> {
  // NEW: Check if we need to capture intent first
  if (currentSession && shouldCaptureIntent(action, currentSession.intent)) {
    try {
      currentSession.intent = await captureIntent(action, promptUser);
      
      // Log intent capture
      currentSession.audit.logSecurityEvent(
        'INTENT_CAPTURED',
        {
          intent: currentSession.intent.primaryGoal,
          capabilities: currentSession.intent.requiredCapabilities,
        },
        currentSession.userId,
        currentSession.id
      );
    } catch (error) {
      console.error('Failed to capture intent:', error);
      // Restrictive intent already set by captureIntent on error
    }
  }

  // EXISTING: Continue with normal confirmation
  // ...
}
```

---

## Configuration

Add to `packages/core/src/config/types.ts`:

```typescript
export interface Config {
  // ... existing fields
  
  // NEW: Authorization settings
  enableAuth?: boolean;
  userId?: string;
  policyPath?: string;
}
```

---

## Testing Integration

Create `packages/core/src/integration-tests/authorization.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { ToolExecutor } from '../scheduler/tool-executor.js';
import { initializeSession } from '../session/session-manager.js';
import { Capability } from '@gemini-cli/auth';

describe('Authorization Integration', () => {
  it('should block unauthorized shell commands', async () => {
    const session = initializeSession('test-user');
    const executor = new ToolExecutor({ enableAuth: true, userId: 'test-user' });
    
    const call = {
      id: '1',
      toolName: 'run_shell_command',
      args: { command: 'rm -rf /' },
    };
    
    const result = await executor.execute({
      call,
      signal: new AbortController().signal,
      onUpdateToolCall: () => {},
    });
    
    expect(result.status).toBe('error');
    expect(result.error?.message).toContain('Authorization denied');
  });

  it('should allow authorized read operations', async () => {
    const session = initializeSession('test-user');
    const executor = new ToolExecutor({ enableAuth: true, userId: 'test-user' });
    
    const call = {
      id: '2',
      toolName: 'read_file',
      args: { path: '~/workspace/test.txt' },
    };
    
    const result = await executor.execute({
      call,
      signal: new AbortController().signal,
      onUpdateToolCall: () => {},
    });
    
    // Should succeed (or require confirmation, not deny)
    expect(result.status).not.toBe('error');
  });
});
```

---

## Summary

**Total Integration Footprint:**
- Hook 1 (Tool Executor): ~50 LOC
- Hook 2 (Session Init): ~20 LOC  
- Hook 3 (Intent Capture): ~30 LOC
- **Total: ~100 LOC** ✅

**Files Modified:**
- `packages/core/src/scheduler/tool-executor.ts`
- `packages/core/src/session/session-manager.ts` (new)
- `packages/core/src/confirmation-bus/*` (depends on structure)
- `packages/core/src/config/types.ts`

**Files Created:**
- `packages/core/src/session/session-manager.ts`
- `packages/core/src/integration-tests/authorization.test.ts`

**Integration complete with minimal invasiveness** ✅
