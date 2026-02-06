# AWS WAF Rule Generator Agent

An AI Security Agent that automates the generation of AWS WAF (Web Application Firewall) rules from CVE vulnerability data.

## Features

- **AI-Powered Rule Generation**: Uses LLMs to analyze vulnerabilities and generate appropriate WAF rules
- **Exploit Context Enrichment**: Fetches and analyzes exploit example URLs for more accurate rule generation
- **Multi-Provider Support**: Works with OpenAI, Anthropic, and Google AI providers
- **Schema Validation**: Uses Zod for strict AWS WAF rule schema validation
- **Semantic Validation**: Additional checks for rule logic correctness
- **Self-Correction Loop**: Automatically retries and fixes generation errors

## Quick Start

### Prerequisites

- Node.js 20.x or later
- An OpenAI API key (or Anthropic/Google API key)

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd aws-waf-rule-generator

# Install dependencies
npm install

# Copy environment file and add your API key
cp .env.example .env
# Edit .env and add your OPENAI_API_KEY
```

### Usage

#### Generate a WAF Rule

```bash
# Basic usage
npx tsx src/index.ts generate --cve CVE-2025-53770

# With verbose output
npx tsx src/index.ts generate --cve CVE-2025-53770 --verbose

# Save to file
npx tsx src/index.ts generate --cve CVE-2025-53770 --output rule.json

# Use a different LLM provider
npx tsx src/index.ts generate --cve CVE-2025-53770 --provider anthropic
```

#### List Available CVEs

```bash
npx tsx src/index.ts list
```

#### View CVE Details

```bash
npx tsx src/index.ts info CVE-2025-53770
```

#### Validate a WAF Rule

```bash
npx tsx src/index.ts validate rule.json
```

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `OPENAI_API_KEY` | OpenAI API key | Yes (if using OpenAI) |
| `ANTHROPIC_API_KEY` | Anthropic API key | Yes (if using Anthropic) |
| `GOOGLE_GENERATIVE_AI_API_KEY` | Google AI API key | Yes (if using Google) |
| `LLM_PROVIDER` | Provider to use: `openai`, `anthropic`, `google` | No (default: `openai`) |

### CLI Options

| Option | Description |
|--------|-------------|
| `--cve <id>` | CVE ID to generate a rule for (required) |
| `--provider <name>` | LLM provider to use |
| `--output <file>` | Output file path (default: stdout) |
| `--no-fetch` | Skip fetching exploit URLs |
| `--verbose` | Enable verbose logging |
| `--max-attempts <n>` | Maximum generation attempts (default: 3) |

## Example Output

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
        },
        {
          "ByteMatchStatement": {
            "SearchString": "POST",
            "FieldToMatch": { "Method": {} },
            "TextTransformations": [{ "Priority": 0, "Type": "NONE" }],
            "PositionalConstraint": "EXACTLY"
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

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        CLI Interface                             │
│                      (src/index.ts)                              │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                     WAF Rule Generator                           │
│                   (src/agent/generator.ts)                       │
│  ┌─────────────┐  ┌──────────────────┐  ┌───────────────────┐  │
│  │ Fetch Vuln  │→ │ Fetch Exploit    │→ │ Generate with     │  │
│  │ from DB     │  │ Context (URLs)   │  │ LLM + Retry Loop  │  │
│  └─────────────┘  └──────────────────┘  └───────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Validation Layer                              │
│  ┌─────────────────────┐     ┌───────────────────────────────┐  │
│  │ Zod Schema          │     │ Semantic Validation           │  │
│  │ (AWS WAF format)    │     │ (Logic & best practices)      │  │
│  └─────────────────────┘     └───────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Testing

```bash
# Run all tests
npm test

# Run tests once
npm run test:run

# Type checking
npm run typecheck
```

## Project Structure

```
src/
├── index.ts              # CLI entry point
├── agent/
│   ├── generator.ts      # Core WAF rule generation logic
│   └── prompts.ts        # System prompts and templates
├── schemas/
│   └── waf-rule.ts       # Zod schema for AWS WAF rules
├── db/
│   └── vulnerabilities.ts # Vulnerability data store
├── enrichment/
│   └── exploit-fetcher.ts # Exploit URL fetching & analysis
├── validation/
│   └── semantic.ts       # Semantic rule validation
└── utils/
    └── config.ts         # Environment configuration
tests/
├── schemas.test.ts       # Schema validation tests
└── validation.test.ts    # Semantic validation tests
```

## Production Deployment

See [docs/PRODUCTION.md](docs/PRODUCTION.md) for the production roadmap including:
- Deployment strategies
- Scaling considerations
- Monitoring and observability
- Security hardening
- CI/CD pipeline recommendations

## Security Considerations

1. **API Key Management**: Store API keys in environment variables, never commit them
2. **Input Validation**: CVE IDs are validated before processing
3. **Output Sanitization**: Generated rules are validated against AWS WAF schema
4. **Prompt Injection**: User input is structured (CVE-ID format only), not passed directly to prompts
5. **Rate Limiting**: Consider implementing rate limits in production

## License

MIT
