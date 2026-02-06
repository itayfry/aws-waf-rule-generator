# AWS WAF Rule Generator - Implementation Summary

## Project Overview

Built an AI Security Agent that generates AWS WAF rules from CVE vulnerability data using the Vercel AI SDK and TypeScript.

## Tech Stack

- **Runtime**: Node.js + TypeScript
- **AI SDK**: Vercel AI SDK with `generateObject` for structured output
- **Schema Validation**: Zod (integrated with Vercel AI SDK)
- **LLM Providers**: OpenAI (default), Anthropic, Google (swappable via env var)
- **Testing**: Vitest
- **CLI**: Commander.js

## Key Architecture Decisions

1. **Chose Vercel AI SDK over Mastra/LangGraph**: The flow is linear (fetch → enrich → generate → validate → retry), so the native `generateObject` with Zod is sufficient without added complexity.

2. **Exploit URL Enrichment**: The agent fetches `exploit_examples_url` articles and uses a cheaper LLM model (gpt-4o-mini) to extract attack patterns, endpoints, and payload signatures. This provides richer context for more accurate WAF rule generation.

3. **Two-Layer Validation**:
   - **Schema validation**: Zod schema enforces AWS WAF JSON structure
   - **Semantic validation**: Checks rule logic (e.g., must have Block action, proper transformations)

4. **Self-Correction Loop**: If validation fails, the agent retries with error context in the prompt.

## Project Structure

```
src/
├── index.ts              # CLI entry point (uses dotenv/config)
├── agent/
│   ├── generator.ts      # Core generation with retry logic
│   └── prompts.ts        # System prompts and templates
├── schemas/
│   └── waf-rule.ts       # Comprehensive AWS WAF Zod schema
├── db/
│   └── vulnerabilities.ts # Mock database with 4 sample CVEs
├── enrichment/
│   └── exploit-fetcher.ts # Fetches and analyzes exploit URLs
├── validation/
│   └── semantic.ts       # Semantic validation checks
└── utils/
    └── config.ts         # Multi-provider configuration
```

## CLI Commands

```bash
# Generate a WAF rule
npx tsx src/index.ts generate --cve CVE-2025-53770 --verbose

# List available CVEs
npx tsx src/index.ts list

# View CVE details
npx tsx src/index.ts info CVE-2025-53770

# Validate a rule file
npx tsx src/index.ts validate rule.json
```

## Key Files

| File | Purpose |
|------|---------|
| `src/schemas/waf-rule.ts` | Comprehensive Zod schema for AWS WAF rules with recursive AND/OR/NOT support |
| `src/agent/generator.ts` | Core `generateWafRule()` function with exploit enrichment and retry logic |
| `src/enrichment/exploit-fetcher.ts` | Fetches exploit URLs, extracts attack patterns via LLM |
| `src/agent/prompts.ts` | System prompt with WAF rule examples and best practices |
| `docs/PRODUCTION.md` | Production roadmap (deployment, scaling, security, CI/CD) |

## Known Issues / Notes

1. **Recursive Schema Warning**: The Vercel AI SDK shows warnings about recursive references in the Zod schema (for nested AND/OR/NOT statements). This is handled gracefully - the SDK falls back to untyped validation for those fields.

2. **Environment Variables**: The project uses `dotenv/config` to load `.env` file. Required keys:
   - `OPENAI_API_KEY` (or `ANTHROPIC_API_KEY` / `GOOGLE_GENERATIVE_AI_API_KEY`)
   - Optional: `LLM_PROVIDER` to switch providers

3. **Tests**: 24 tests covering schema validation and semantic validation (run with `npm run test:run`)

## Sample Generated Output

The agent generates valid AWS WAF rules like:

```json
{
  "Name": "Block-CVE-2025-53770-SharePoint-RCE",
  "Priority": 1,
  "Statement": {
    "AndStatement": {
      "Statements": [
        {
          "ByteMatchStatement": {
            "SearchString": "/_api/",
            "FieldToMatch": { "UriPath": {} },
            "TextTransformations": [
              { "Priority": 0, "Type": "URL_DECODE" },
              { "Priority": 1, "Type": "LOWERCASE" }
            ],
            "PositionalConstraint": "CONTAINS"
          }
        }
      ]
    }
  },
  "Action": { "Block": {} },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "BlockCVE2025_53770"
  }
}
```

## Dependencies

Main dependencies from package.json:
- `ai` (Vercel AI SDK)
- `@ai-sdk/openai`, `@ai-sdk/anthropic`, `@ai-sdk/google`
- `zod`
- `commander`
- `dotenv`
