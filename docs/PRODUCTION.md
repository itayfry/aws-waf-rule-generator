# Production Roadmap

This document outlines the strategic plan for scaling and integrating the AWS WAF Rule Generator Agent into a production environment.

## Table of Contents

1. [Deployment Architecture](#deployment-architecture)
2. [Scaling Strategy](#scaling-strategy)
3. [Integration Points](#integration-points)
4. [Monitoring & Observability](#monitoring--observability)
5. [Security Hardening](#security-hardening)
6. [CI/CD Pipeline](#cicd-pipeline)
7. [Cost Optimization](#cost-optimization)
8. [Disaster Recovery](#disaster-recovery)

---

## Deployment Architecture

### Recommended Stack

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Compute | AWS Lambda / Vercel Functions | Serverless, auto-scaling, pay-per-use |
| API Gateway | AWS API Gateway / Vercel Edge | Rate limiting, authentication |
| Queue | AWS SQS / Redis Queue | Async processing for batch jobs |
| Database | PostgreSQL / DynamoDB | Store CVE data and generated rules |
| Cache | Redis / ElastiCache | Cache generated rules, reduce LLM calls |
| Secrets | AWS Secrets Manager | Secure API key storage |

### Architecture Diagram

```
┌──────────────┐     ┌─────────────────┐     ┌───────────────────┐
│   Client     │────▶│   API Gateway   │────▶│  Lambda/Vercel    │
│  (API/CLI)   │     │  (Rate Limit)   │     │  Function         │
└──────────────┘     └─────────────────┘     └───────────────────┘
                                                      │
                     ┌────────────────────────────────┴────────────┐
                     │                                             │
                     ▼                                             ▼
              ┌─────────────┐                              ┌───────────────┐
              │   Redis     │                              │   SQS Queue   │
              │   Cache     │                              │  (Async Jobs) │
              └─────────────┘                              └───────────────┘
                     │                                             │
                     ▼                                             ▼
              ┌─────────────┐                              ┌───────────────┐
              │  Database   │                              │  Worker       │
              │  (CVE Data) │                              │  Lambda       │
              └─────────────┘                              └───────────────┘
                                                                   │
                                                                   ▼
                                                           ┌───────────────┐
                                                           │  LLM Provider │
                                                           │  (OpenAI/etc) │
                                                           └───────────────┘
```

### Deployment Options

#### Option 1: Vercel (Recommended for MVP)

```typescript
// api/generate.ts - Vercel Serverless Function
import { generateWafRule } from '../src/agent/generator';

export default async function handler(req, res) {
  const { cveId } = req.body;
  const rule = await generateWafRule(cveId);
  res.json(rule);
}
```

**Pros**: Easy deployment, built-in edge caching, automatic scaling
**Cons**: Cold start latency, 10s execution limit (can extend with streaming)

#### Option 2: AWS Lambda + API Gateway

**Pros**: Full AWS integration, longer timeouts, VPC support
**Cons**: More complex setup, higher operational overhead

---

## Scaling Strategy

### Horizontal Scaling

1. **Stateless Functions**: Each invocation is independent
2. **Connection Pooling**: Reuse database connections across warm starts
3. **Queue-Based Processing**: Decouple request handling from LLM calls

### Capacity Planning

| Load Level | Requests/min | Strategy |
|------------|--------------|----------|
| Low (<10)  | 10           | Single function, direct LLM calls |
| Medium     | 100          | Multiple concurrent functions, caching |
| High       | 1000+        | Queue + workers, aggressive caching |

### Caching Strategy

```typescript
// Cache generated rules by CVE-ID + model version
const cacheKey = `waf-rule:${cveId}:${modelVersion}`;
const cached = await redis.get(cacheKey);

if (cached) {
  return JSON.parse(cached);
}

const rule = await generateWafRule(vulnerability);
await redis.set(cacheKey, JSON.stringify(rule), 'EX', 86400); // 24h TTL
```

---

## Integration Points

### 1. AWS WAF Integration

```typescript
import { WAFv2Client, CreateRuleCommand } from '@aws-sdk/client-wafv2';

async function deployRule(rule: WafRule, webAclId: string) {
  const client = new WAFv2Client({ region: 'us-east-1' });
  
  await client.send(new CreateRuleCommand({
    Name: rule.Name,
    Scope: 'REGIONAL', // or 'CLOUDFRONT'
    // ... rule configuration
  }));
}
```

### 2. SIEM Integration

Send generated rules to SIEM for audit logging:

```typescript
interface AuditEvent {
  timestamp: string;
  cveId: string;
  ruleGenerated: boolean;
  ruleName: string;
  attempts: number;
  provider: string;
}

async function logToSiem(event: AuditEvent) {
  // Send to Splunk, Datadog, etc.
}
```

### 3. Vulnerability Scanner Integration

Trigger rule generation from vulnerability scanners:

```typescript
// Webhook endpoint for scanner integration
app.post('/webhook/vulnerability', async (req, res) => {
  const { cveId, severity } = req.body;
  
  if (severity === 'critical' || severity === 'high') {
    await queueRuleGeneration(cveId);
  }
  
  res.status(202).json({ queued: true });
});
```

---

## Monitoring & Observability

### Key Metrics

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| `generation.success_rate` | % of successful generations | < 95% |
| `generation.latency_p99` | 99th percentile latency | > 30s |
| `generation.attempts` | Average attempts per rule | > 2 |
| `llm.token_usage` | Tokens consumed per request | > 5000 |
| `llm.cost_per_rule` | Cost per generated rule | > $0.10 |
| `validation.failure_rate` | Schema/semantic failures | > 10% |

### Logging Structure

```typescript
interface GenerationLog {
  requestId: string;
  timestamp: string;
  cveId: string;
  provider: string;
  model: string;
  success: boolean;
  attempts: number;
  latencyMs: number;
  tokensUsed: number;
  error?: string;
  validationErrors?: string[];
}
```

### Dashboards

1. **Operations Dashboard**
   - Request volume
   - Success/failure rates
   - Latency distribution

2. **Cost Dashboard**
   - Token usage by provider
   - Cost per rule
   - Monthly spending forecast

3. **Quality Dashboard**
   - Validation failure breakdown
   - Retry rates
   - Rule coverage by CVE severity

---

## Security Hardening

### 1. API Authentication

```typescript
// JWT validation middleware
async function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  
  try {
    const decoded = await verifyJwt(token);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ error: 'Unauthorized' });
  }
}
```

### 2. Rate Limiting

```typescript
import { Ratelimit } from '@upstash/ratelimit';
import { Redis } from '@upstash/redis';

const ratelimit = new Ratelimit({
  redis: Redis.fromEnv(),
  limiter: Ratelimit.slidingWindow(10, '1m'), // 10 requests per minute
});

async function rateLimitMiddleware(req, res, next) {
  const { success } = await ratelimit.limit(req.user.id);
  
  if (!success) {
    return res.status(429).json({ error: 'Rate limit exceeded' });
  }
  
  next();
}
```

### 3. Input Validation

```typescript
const CveIdSchema = z.string().regex(/^CVE-\d{4}-\d{4,}$/i);

function validateInput(cveId: string) {
  const result = CveIdSchema.safeParse(cveId);
  if (!result.success) {
    throw new ValidationError('Invalid CVE ID format');
  }
  return result.data.toUpperCase();
}
```

### 4. Secrets Management

```typescript
// Use AWS Secrets Manager in production
import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';

async function getApiKey(secretName: string): Promise<string> {
  const client = new SecretsManagerClient({ region: 'us-east-1' });
  const response = await client.send(new GetSecretValueCommand({ SecretId: secretName }));
  return response.SecretString!;
}
```

### 5. Prompt Injection Prevention

- CVE IDs are validated against strict regex pattern
- User input is never directly concatenated into prompts
- All LLM outputs are validated against strict schemas

---

## CI/CD Pipeline

### GitHub Actions Workflow

```yaml
name: CI/CD

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - run: npm run typecheck
      - run: npm run test:run
      
  deploy:
    needs: test
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vercel/action@v4
        with:
          vercel-token: ${{ secrets.VERCEL_TOKEN }}
```

### Quality Gates

1. **Type Checking**: `tsc --noEmit`
2. **Unit Tests**: 80% coverage minimum
3. **Integration Tests**: Test against mock LLM responses
4. **Security Scan**: Dependabot + Snyk

---

## Cost Optimization

### Token Budget Management

```typescript
interface TokenBudget {
  maxInputTokens: number;
  maxOutputTokens: number;
  maxCostPerRule: number;
}

const DEFAULT_BUDGET: TokenBudget = {
  maxInputTokens: 4000,
  maxOutputTokens: 2000,
  maxCostPerRule: 0.10, // USD
};

function estimateCost(inputTokens: number, outputTokens: number): number {
  // GPT-4o pricing
  return (inputTokens * 0.005 + outputTokens * 0.015) / 1000;
}
```

### Cost Reduction Strategies

1. **Caching**: Cache rules for 24h (CVEs don't change frequently)
2. **Model Selection**: Use `gpt-4o-mini` for exploit context extraction
3. **Prompt Optimization**: Keep prompts concise, use examples efficiently
4. **Batch Processing**: Process multiple CVEs in a single context when possible

### Expected Costs

| Volume | Estimated Monthly Cost |
|--------|----------------------|
| 100 rules/month | ~$10-20 |
| 1,000 rules/month | ~$100-200 |
| 10,000 rules/month | ~$800-1,500 |

---

## Disaster Recovery

### Backup Strategy

1. **CVE Database**: Daily backups, 30-day retention
2. **Generated Rules**: Store in S3 with versioning
3. **Configuration**: Infrastructure as Code (Terraform/Pulumi)

### Failover Plan

1. **LLM Provider Failover**: Automatic switch to backup provider
   ```typescript
   const providers = ['openai', 'anthropic', 'google'];
   
   async function generateWithFailover(vuln: Vulnerability) {
     for (const provider of providers) {
       try {
         return await generateWafRule(vuln, { provider });
       } catch (error) {
         console.error(`${provider} failed, trying next...`);
       }
     }
     throw new Error('All providers failed');
   }
   ```

2. **Region Failover**: Deploy to multiple AWS regions
3. **Graceful Degradation**: Return cached rules if generation fails

### Recovery Time Objectives

| Scenario | RTO | RPO |
|----------|-----|-----|
| LLM provider outage | 1 minute | 0 (failover) |
| Database corruption | 1 hour | 24 hours |
| Complete infrastructure failure | 4 hours | 24 hours |
