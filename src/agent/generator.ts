import { generateObject } from 'ai';
import { WafRuleSchema, type WafRule } from '../schemas/waf-rule.js';
import type { VulnerabilityRecord } from '../db/vulnerabilities.js';
import {
  fetchExploitContext,
  createBasicContext,
  type ExploitContext,
} from '../enrichment/exploit-fetcher.js';
import {
  WAF_SYSTEM_PROMPT,
  buildGenerationPrompt,
  buildCorrectionPrompt,
} from './prompts.js';
import { validateRuleSemantics, type ValidationResult } from '../validation/semantic.js';
import { getModel } from '../utils/config.js';

export interface GenerationOptions {
  /** Maximum number of generation attempts */
  maxAttempts?: number;
  /** Whether to fetch exploit URLs for additional context */
  fetchExploitUrls?: boolean;
  /** Timeout for fetching exploit URLs (ms) */
  fetchTimeout?: number;
  /** Enable verbose logging */
  verbose?: boolean;
}

export interface GenerationResult {
  rule: WafRule;
  attempts: number;
  exploitContextUsed: boolean;
  validationPassed: boolean;
}

/**
 * Generate a WAF rule for a specific vulnerability
 */
export async function generateWafRule(
  vulnerability: VulnerabilityRecord,
  options: GenerationOptions = {}
): Promise<GenerationResult> {
  const {
    maxAttempts = 3,
    fetchExploitUrls = true,
    fetchTimeout = 5000,
    verbose = false,
  } = options;

  const log = verbose ? console.log.bind(console) : () => {};

  // Step 1: Enrich with exploit context
  log(`\n[1/3] Fetching exploit context for ${vulnerability.cve_id}...`);
  
  let exploitContext: ExploitContext;
  let exploitContextUsed = false;

  if (fetchExploitUrls && vulnerability.exploit_examples_url.length > 0) {
    try {
      exploitContext = await fetchExploitContext(
        vulnerability.exploit_examples_url,
        { timeoutMs: fetchTimeout }
      );
      exploitContextUsed = exploitContext.summary !== 'No exploit context available';
      log(`  Found ${exploitContext.targetEndpoints.length} endpoints, ${exploitContext.payloadSignatures.length} signatures`);
    } catch (error) {
      log(`  Warning: Failed to fetch exploit context: ${error}`);
      exploitContext = createBasicContext(vulnerability.description, vulnerability.product);
    }
  } else {
    exploitContext = createBasicContext(vulnerability.description, vulnerability.product);
  }

  // Step 2: Generate WAF rule with retry logic
  log(`\n[2/3] Generating WAF rule...`);
  
  let lastError: Error | null = null;
  let lastAttempt: unknown = null;
  let attempts = 0;

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    attempts = attempt;
    log(`  Attempt ${attempt}/${maxAttempts}...`);

    try {
      const prompt = attempt === 1
        ? buildGenerationPrompt(vulnerability, exploitContext)
        : buildCorrectionPrompt(vulnerability, exploitContext, lastError!, lastAttempt);

      const { object: wafRule } = await generateObject({
        model: getModel('main'),
        schema: WafRuleSchema,
        system: WAF_SYSTEM_PROMPT,
        prompt,
        maxRetries: 2, // Vercel AI SDK's built-in retry for schema validation
      });

      // Step 3: Semantic validation
      log(`\n[3/3] Validating rule semantics...`);
      const validation = await validateRuleSemantics(wafRule, vulnerability);

      if (validation.valid) {
        log(`  Validation passed!`);
        return {
          rule: wafRule,
          attempts,
          exploitContextUsed,
          validationPassed: true,
        };
      }

      // Semantic validation failed - retry with error context
      log(`  Validation failed: ${validation.errors.join(', ')}`);
      lastError = new Error(`Semantic validation failed: ${validation.errors.join(', ')}`);
      lastAttempt = wafRule;

    } catch (error) {
      log(`  Generation error: ${error}`);
      lastError = error instanceof Error ? error : new Error(String(error));
      lastAttempt = null;
    }
  }

  // All attempts failed
  throw new Error(
    `Failed to generate valid WAF rule after ${maxAttempts} attempts. Last error: ${lastError?.message}`
  );
}

/**
 * Generate WAF rules for multiple vulnerabilities
 */
export async function generateWafRulesForCves(
  vulnerabilities: VulnerabilityRecord[],
  options: GenerationOptions = {}
): Promise<Map<string, GenerationResult | Error>> {
  const results = new Map<string, GenerationResult | Error>();

  for (const vuln of vulnerabilities) {
    try {
      const result = await generateWafRule(vuln, options);
      results.set(vuln.cve_id, result);
    } catch (error) {
      results.set(vuln.cve_id, error instanceof Error ? error : new Error(String(error)));
    }
  }

  return results;
}
