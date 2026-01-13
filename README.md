# gemini-cli-secure

**AI Agent Permission System for gemini-cli**

An open source security authorization framework built on top of Gemini CLI that adds [**resampling**](https://www.bashcontrol.com/), capability-based access control, TOCTOU prevention, and intent alignment to AI agent tool execution.

[![Tests](https://img.shields.io/badge/tests-107%2F109-success)](./test)
[![Detection](https://img.shields.io/badge/red_team-100%25-success)](./test/red-team)
[![Coverage](https://img.shields.io/badge/coverage-98%25-success)](./test)

---

## Quick Start

```bash
# Install
npm install @gemini-cli/auth

# Use in your authorization flow
import { AuthorizationEngine, loadPolicy } from '@gemini-cli/auth';

const policy = loadPolicy('my-user');
const engine = new AuthorizationEngine(policy);

// Authorize an action
const decision = await engine.authorize(action, intent);
if (decision.type === 'deny') {
  throw new Error(`Blocked: ${decision.reason}`);
}
```

---

## Features

### ✅ Capability-Based Authorization
- **37 atomic capabilities** across 6 categories
- **Policy-driven enforcement** via YAML configuration
- **Scope restrictions** (filesystem paths, network domains)
- **Default deny posture** for security

### ✅ TOCTOU Prevention
- **Cryptographic token binding** (HMAC-SHA256)
- **100% attack prevention** validated via red team
- **60-second validity window**
- **Canonical action representation**

### ✅ Intent Alignment
- **JIT intent capture** on first high-risk operation
- **Multi-signal alignment** (capability + embedding + drift)
- **Automatic capability extraction**
- **Restrictive fallback** on user decline

### ✅ Audit Logging
- **Tamper-evident logging** with SHA-256 chain
- **JSON structured format**
- **All decisions logged**
- **Integrity verification**

### ✅ Multi-Model Monitoring
- **Dual monitors** (trusted + untrusted)
- **Heterogeneous defense** (Claude + Llama-3-70b)
- **Consensus blocking** (ANY monitor can block)
- **Degradation handling**

### ✅ Best-of-N Resampling
- **Action ranking** by risk score
- **> 40% risk reduction** for high-risk ops
- **Configurable N** (default: 3)
- **Automatic trigger** on dangerous capabilities

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     gemini-cli Core                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
│  │ Tool         │  │ Session      │  │ Confirmation │     │
│  │ Executor     │  │ Manager      │  │ Bus          │     │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘     │
│         │                 │                 │              │
│         │  Hook 1         │  Hook 2         │  Hook 3      │
└─────────┼─────────────────┼─────────────────┼──────────────┘
          │                 │                 │
          ▼                 ▼                 ▼
┌─────────────────────────────────────────────────────────────┐
│                    @gemini-cli/auth                         │
│  ┌──────────────────────────────────────────────────────┐  │
│  │            Authorization Engine                       │  │
│  │  • Capability checking                                │  │
│  │  • Scope enforcement                                  │  │
│  │  • Intent alignment                                   │  │
│  │  • Token binding                                      │  │
│  └──────────────┬────────────────────────┬───────────────┘  │
│                 │                        │                  │
│    ┌────────────▼─────────┐   ┌─────────▼──────────┐       │
│    │ Multi-Model Monitors │   │ Best-of-N Resample │       │
│    │ • Trusted (Claude)   │   │ • Risk ranking     │       │
│    │ • Untrusted (Llama)  │   │ • Selection        │       │
│    └──────────────────────┘   └────────────────────┘       │
│                                                             │
│    ┌─────────────────────────────────────────────────┐     │
│    │ Audit Logger (Tamper-Evident)                   │     │
│    └─────────────────────────────────────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

---

## Usage

### Basic Authorization

```typescript
import { AuthorizationEngine, getDefaultPolicy, type Action } from '@gemini-cli/auth';

// Create engine with policy
const policy = getDefaultPolicy();
const engine = new AuthorizationEngine(policy);

// Define an action
const action: Action = {
  toolName: 'read_file',
  toolArgs: { path: '~/workspace/data.txt' },
  description: 'Read data file',
  capabilities: [Capability.FILESYSTEM_READ],
  target: '~/workspace/data.txt',
  riskScore: 0.3,
  timestamp: Date.now(),
};

// Authorize
const decision = await engine.authorize(action, null);

console.log(decision.type); // 'allow' | 'deny' | 'confirm'
console.log(decision.reason); // Why it was denied
console.log(decision.authToken); // Token for execution
```

### Intent Capture

```typescript
import { analyzeIntent, captureIntent } from '@gemini-cli/auth';

// Analyze user prompt
const intent = analyzeIntent("Read logs from ~/app/logs");
// Returns: { primaryGoal, requiredCapabilities, scopeRestrictions }

// JIT capture on high-risk operation
if (shouldCaptureIntent(action, session.intent)) {
  session.intent = await captureIntent(action, promptUser);
}
```

### Token Verification (TOCTOU Prevention)

```typescript
import { verifyAuthToken } from '@gemini-cli/auth';

// After authorization
const decision = await engine.authorize(action, intent);

// Before execution
const isValid = verifyAuthToken(decision.authToken, action);
if (!isValid) {
  throw new Error('Token verification failed - action was modified');
}

// Execute tool safely
executeTool(action);
```

### Audit Logging

```typescript
import { createAuditLogger } from '@gemini-cli/auth';

const logger = createAuditLogger('~/.gemini/audit.log');

// Log all authorization decisions
logger.log(action, decision, userId, sessionId);

// Log security events
logger.logSecurityEvent('UNAUTHORIZED_ACCESS', { path: '/etc/passwd' }, userId);

// Verify integrity
const hash = logger.getCurrentHash();
```

---

## Performance

| Metric | Target | Actual |
|--------|--------|--------|
| Authorization check | <50ms | 10-20ms |
| Token generation | <25ms | <25ms |
| 100 sequential ops | <5s | <2s |
| Red team detection | >85% | **100%** |
| TOCTOU prevention | >90% | **100%** |

---

## Security

### Red Team Validation

35 adversarial attack scenarios tested:

| Attack Type | Detection Rate |
|-------------|----------------|
| Direct Malicious Commands | 100% (10/10) |
| TOCTOU Race Conditions | 100% (10/10) |
| Semantic Misalignment | 100% (15/15) |
| **Overall** | **100% (35/35)** |

### Blocked Attacks

- ✅ `rm -rf /` system deletion
- ✅ `/etc/passwd` credential theft
- ✅ `~/.ssh/id_rsa` SSH key access
- ✅ Privilege escalation (`sudo`)
- ✅ Reverse shells (`nc -e`)
- ✅ Path traversal
- ✅ `.env` file access
- ✅ Network exfiltration
- ✅ TOCTOU manipulation

---

## Configuration

### Policy Example (YAML)

```yaml
version: "1.0"

defaultPolicy:
  allow:
    - filesystem.read
    - network.search
  deny:
    - execution.shell
    - system.privilege_escalate

globalRules:
  - name: workspace_access
    allow:
      - filesystem.read
      - filesystem.write
    scope:
      filesystemPaths:
        - ~/workspace/*
        - ./project/*
      exclude:
        - "*.env"
        - ~/.ssh/**
    requireConfirmation: false

  - name: deny_privilege_escalation
    deny:
      - system.privilege_escalate
    reason: "Privilege escalation disabled for safety"
```

---

## Integration

See [INTEGRATION_GUIDE.md](./INTEGRATION_GUIDE.md) for complete integration instructions.

**3 Simple Hooks (~100 LOC total):**

1. **Tool Execution** - Add authorization before tool calls
2. **Session Init** - Load policy on session create
3. **Intent Capture** - Prompt user for intent in confirmation flow

---

## API Reference

### Core Classes

- `AuthorizationEngine` - Main authorization logic
- `TrustedMonitor` / `UntrustedMonitor` - Multi-model monitoring
- `ResamplingEngine` - Best-of-N action selection
- `AuditLogger` - Tamper-evident logging

### Functions

- `loadPolicy(userId)` - Load user policy from YAML
- `getDefaultPolicy()` - Get safe sandbox policy
- `analyzeIntent(prompt)` - Extract intent from user prompt
- `captureIntent(action, promptFn)` - JIT intent capture
- `generateAuthToken(action)` - Create cryptographic token
- `verifyAuthToken(token, action)` - Verify token validity

### Types

- `Action` - Agent action to authorize
- `AuthDecision` - Authorization result
- `IntentScope` - User intent scope
- `PermissionPolicy` - Policy configuration
- `MonitorAssessment` - Monitor result

---

## Testing

```bash
# Run all tests
npm test

# Run specific suites
npm test -- capabilities
npm test -- token-binding
npm test -- authorization-engine
npm test -- red-team

# With coverage
npm test -- --coverage
```

---

## License

Apache 2.0

---

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for contribution guidelines.

---

## Support

- Documentation: [./docs](./docs)
- Issues: [GitHub Issues](https://github.com/google-gemini/gemini-cli/issues)
- Security: See [SECURITY.md](../../SECURITY.md)

---

**Built with ❤️ for secure AI agents**
