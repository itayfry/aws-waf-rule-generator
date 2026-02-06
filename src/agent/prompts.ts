import type { VulnerabilityRecord } from '../db/vulnerabilities.js';
import type { ExploitContext } from '../enrichment/exploit-fetcher.js';

/**
 * System prompt for WAF rule generation
 */
export const WAF_SYSTEM_PROMPT = `You are an expert AWS WAF (Web Application Firewall) rule engineer. Your task is to generate effective WAF rules that block specific exploits while minimizing false positives.

## AWS WAF Rule Structure

A WAF rule consists of:
1. **Name**: Alphanumeric with hyphens/underscores (e.g., "Block-CVE-2025-53770")
2. **Priority**: Integer (0-based, lower = evaluated first)
3. **Statement**: The matching logic (ByteMatch, Regex, SQLi, XSS, Size, Geo, or compound AND/OR/NOT)
4. **Action**: What to do on match (Block, Allow, Count, Captcha, Challenge)
5. **VisibilityConfig**: CloudWatch metrics configuration

## Statement Types You Can Use

### ByteMatchStatement
Match specific byte patterns in requests:
\`\`\`json
{
  "ByteMatchStatement": {
    "SearchString": "/_api/web/",
    "FieldToMatch": { "UriPath": {} },
    "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
    "PositionalConstraint": "CONTAINS"
  }
}
\`\`\`

### RegexMatchStatement
Match regex patterns:
\`\`\`json
{
  "RegexMatchStatement": {
    "RegexString": "\\\\$\\\\{jndi:(ldap|rmi|dns):",
    "FieldToMatch": { "Body": { "OversizeHandling": "CONTINUE" } },
    "TextTransformations": [{ "Priority": 0, "Type": "URL_DECODE" }]
  }
}
\`\`\`

### Compound Statements (AND/OR/NOT)
Combine multiple conditions:
\`\`\`json
{
  "AndStatement": {
    "Statements": [
      { "ByteMatchStatement": { ... } },
      { "ByteMatchStatement": { ... } }
    ]
  }
}
\`\`\`

## FieldToMatch Options
- \`UriPath\`: The URL path
- \`QueryString\`: The query string
- \`Body\`: Request body (with OversizeHandling)
- \`SingleHeader\`: Specific header by name
- \`Headers\`: All headers (with match pattern)
- \`Method\`: HTTP method
- \`JsonBody\`: JSON body with path matching

## TextTransformations (apply before matching)
- \`NONE\`: No transformation
- \`LOWERCASE\`: Convert to lowercase
- \`URL_DECODE\`: Decode URL encoding
- \`HTML_ENTITY_DECODE\`: Decode HTML entities
- \`BASE64_DECODE\`: Decode Base64
- \`CMD_LINE\`: Normalize command line strings

## Best Practices

1. **Be specific**: Match the exact exploit pattern, not broad categories
2. **Layer transformations**: Use URL_DECODE + LOWERCASE for web requests
3. **Use compound rules**: AND statements reduce false positives
4. **Consider evasion**: Attackers may encode payloads - add appropriate transformations
5. **Prefer ByteMatch over Regex**: ByteMatch is faster when exact patterns are known
6. **Block action**: Use Block for confirmed exploit patterns

## Output Requirements

Generate a single, complete WAF rule that:
1. Effectively blocks the specific vulnerability/exploit
2. Minimizes false positives through precise matching
3. Handles common evasion techniques (encoding, case variation)
4. Has appropriate CloudWatch metrics enabled`;

/**
 * Build the generation prompt for a specific vulnerability
 */
export function buildGenerationPrompt(
  vulnerability: VulnerabilityRecord,
  exploitContext: ExploitContext
): string {
  const parts: string[] = [
    '## Vulnerability Information',
    '',
    `**CVE ID**: ${vulnerability.cve_id}`,
    `**Title**: ${vulnerability.title}`,
    `**Severity**: ${vulnerability.severity.toUpperCase()}`,
    `**Vendor**: ${vulnerability.vendor}`,
    `**Product**: ${vulnerability.product}`,
    '',
    '**Description**:',
    vulnerability.description,
    '',
  ];

  // Add exploit context if available
  if (exploitContext.summary !== 'No exploit context available') {
    parts.push('## Exploit Analysis');
    parts.push('');
    parts.push(`**Summary**: ${exploitContext.summary}`);
    parts.push('');

    if (exploitContext.targetEndpoints.length > 0) {
      parts.push(`**Target Endpoints**: ${exploitContext.targetEndpoints.join(', ')}`);
    }

    if (exploitContext.httpMethods.length > 0) {
      parts.push(`**HTTP Methods**: ${exploitContext.httpMethods.join(', ')}`);
    }

    if (exploitContext.payloadSignatures.length > 0) {
      parts.push(`**Payload Signatures**: ${exploitContext.payloadSignatures.join(', ')}`);
    }

    if (exploitContext.headers.length > 0) {
      parts.push(`**Notable Headers**: ${exploitContext.headers.join(', ')}`);
    }

    if (exploitContext.attackPatterns.length > 0) {
      parts.push('');
      parts.push('**Attack Patterns**:');
      exploitContext.attackPatterns.forEach((pattern) => {
        parts.push(`- ${pattern}`);
      });
    }

    if (exploitContext.bodyPatterns.length > 0) {
      parts.push('');
      parts.push('**Body Patterns**:');
      exploitContext.bodyPatterns.forEach((pattern) => {
        parts.push(`- ${pattern}`);
      });
    }

    parts.push('');
  }

  parts.push('## Task');
  parts.push('');
  parts.push('Generate an AWS WAF rule that blocks this specific exploit.');
  parts.push('The rule should:');
  parts.push('1. Target the specific attack vectors described above');
  parts.push('2. Use appropriate field matching (URI, headers, body as needed)');
  parts.push('3. Apply text transformations to handle encoding variations');
  parts.push('4. Block matching requests');
  parts.push('5. Enable CloudWatch metrics for monitoring');

  return parts.join('\n');
}

/**
 * Build a correction prompt when previous generation failed validation
 */
export function buildCorrectionPrompt(
  vulnerability: VulnerabilityRecord,
  exploitContext: ExploitContext,
  error: Error,
  previousAttempt?: unknown
): string {
  const basePrompt = buildGenerationPrompt(vulnerability, exploitContext);

  const correctionParts = [
    basePrompt,
    '',
    '## Previous Attempt Failed',
    '',
    '**Error**:',
    error.message,
    '',
  ];

  if (previousAttempt) {
    correctionParts.push('**Previous Output** (for reference):');
    correctionParts.push('```json');
    correctionParts.push(JSON.stringify(previousAttempt, null, 2));
    correctionParts.push('```');
    correctionParts.push('');
  }

  correctionParts.push('Please fix the issues and generate a valid WAF rule.');
  correctionParts.push('Pay special attention to:');
  correctionParts.push('1. Valid JSON structure matching the AWS WAF API schema');
  correctionParts.push('2. Correct field names and types');
  correctionParts.push('3. Valid enum values for PositionalConstraint, TextTransformationType, etc.');

  return correctionParts.join('\n');
}
