# Quick Reference

## What This Project Does

AI agent that takes a CVE-ID → fetches vulnerability data → optionally scrapes exploit articles for context → generates an AWS WAF rule using LLM → validates the output.

## How to Run

```bash
# Install deps
npm install

# Set API key in .env
OPENAI_API_KEY=sk-...

# Generate a rule
npx tsx src/index.ts generate --cve CVE-2025-53770 --verbose
```

## How to Modify

- **Add new CVEs**: Edit `src/db/vulnerabilities.ts`
- **Change prompts**: Edit `src/agent/prompts.ts`
- **Adjust validation**: Edit `src/validation/semantic.ts`
- **Switch LLM provider**: Set `LLM_PROVIDER=anthropic` in .env

## Key Design Pattern

```
CVE-ID → Fetch Vuln Data → Fetch Exploit URLs → LLM Extract Patterns
                                                         ↓
                              WAF Rule ← Validate ← LLM Generate
                                 ↓
                            (retry if invalid)
```

## Tests

```bash
npm run test:run  # 24 tests
npm run typecheck # TypeScript validation
```
