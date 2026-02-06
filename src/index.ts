#!/usr/bin/env node

import 'dotenv/config';
import { program } from 'commander';
import { writeFile, mkdir } from 'fs/promises';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import {
  getVulnerabilityByCveId,
  listAvailableCveIds,
  isValidCveId,
} from './db/vulnerabilities.js';
import { generateWafRule, type GenerationOptions } from './agent/generator.js';
import { validateEnvironment, getProvider } from './utils/config.js';

// CLI version
const VERSION = '1.0.0';

program
  .name('waf-rule-generator')
  .description('AI Security Agent that generates AWS WAF rules from CVE data')
  .version(VERSION);

// Main generate command
program
  .command('generate')
  .description('Generate a WAF rule for a specific CVE')
  .requiredOption('--cve <id>', 'CVE ID to generate a rule for (e.g., CVE-2025-53770)')
  .option('--provider <name>', 'LLM provider to use (openai, anthropic, google)', 'openai')
  .option('--output <file>', 'Output file path (default: stdout)')
  .option('--no-fetch', 'Skip fetching exploit URLs for additional context')
  .option('--verbose', 'Enable verbose logging')
  .option('--max-attempts <number>', 'Maximum generation attempts', '3')
  .action(async (options) => {
    try {
      // Set provider if specified
      if (options.provider) {
        process.env.LLM_PROVIDER = options.provider;
      }

      // Validate environment
      validateEnvironment();

      const cveId = options.cve.toUpperCase();

      // Validate CVE ID format
      if (!isValidCveId(cveId)) {
        console.error(`Error: Invalid CVE ID format: ${cveId}`);
        console.error('Expected format: CVE-YYYY-NNNNN (e.g., CVE-2025-53770)');
        process.exit(1);
      }

      // Fetch vulnerability data
      if (options.verbose) {
        console.log(`\nFetching vulnerability data for ${cveId}...`);
      }

      const vulnerability = await getVulnerabilityByCveId(cveId);

      if (!vulnerability) {
        console.error(`Error: CVE ${cveId} not found in database.`);
        const available = await listAvailableCveIds();
        console.error(`\nAvailable CVEs: ${available.join(', ')}`);
        process.exit(1);
      }

      if (options.verbose) {
        console.log(`Found: ${vulnerability.title}`);
        console.log(`Severity: ${vulnerability.severity}`);
        console.log(`Provider: ${getProvider()}`);
      }

      // Generate WAF rule
      const generationOptions: GenerationOptions = {
        maxAttempts: parseInt(options.maxAttempts, 10),
        fetchExploitUrls: options.fetch !== false,
        verbose: options.verbose,
      };

      const result = await generateWafRule(vulnerability, generationOptions);

      // Format output
      const output = JSON.stringify(result.rule, null, 2);

      // Save to generated_wafs folder
      const __dirname = dirname(fileURLToPath(import.meta.url));
      const generatedWafsDir = join(__dirname, '..', 'generated_wafs');
      await mkdir(generatedWafsDir, { recursive: true });
      const savedFilePath = join(generatedWafsDir, `${cveId}.json`);
      await writeFile(savedFilePath, output, 'utf-8');
      console.log(`\nWAF rule saved to ${savedFilePath}`);

      // Write to file or stdout
      if (options.output) {
        await writeFile(options.output, output, 'utf-8');
        console.log(`WAF rule also written to ${options.output}`);
      } else {
        console.log('\n--- Generated WAF Rule ---\n');
        console.log(output);
      }

      // Print generation stats
      if (options.verbose) {
        console.log('\n--- Generation Stats ---');
        console.log(`Attempts: ${result.attempts}`);
        console.log(`Exploit context used: ${result.exploitContextUsed}`);
        console.log(`Validation passed: ${result.validationPassed}`);
      }

    } catch (error) {
      console.error('\nError:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// List available CVEs command
program
  .command('list')
  .description('List available CVEs in the database')
  .action(async () => {
    const cves = await listAvailableCveIds();
    console.log('\nAvailable CVEs:');
    cves.forEach((cve) => console.log(`  - ${cve}`));
    console.log(`\nTotal: ${cves.length} CVEs`);
  });

// Show CVE details command
program
  .command('info <cve>')
  .description('Show details about a specific CVE')
  .action(async (cveId: string) => {
    const normalized = cveId.toUpperCase();

    if (!isValidCveId(normalized)) {
      console.error(`Error: Invalid CVE ID format: ${cveId}`);
      process.exit(1);
    }

    const vulnerability = await getVulnerabilityByCveId(normalized);

    if (!vulnerability) {
      console.error(`Error: CVE ${normalized} not found.`);
      process.exit(1);
    }

    console.log('\n--- CVE Details ---\n');
    console.log(`CVE ID: ${vulnerability.cve_id}`);
    console.log(`Title: ${vulnerability.title}`);
    console.log(`Severity: ${vulnerability.severity.toUpperCase()}`);
    console.log(`Vendor: ${vulnerability.vendor}`);
    console.log(`Product: ${vulnerability.product}`);
    console.log(`\nDescription:`);
    console.log(`  ${vulnerability.description}`);
    console.log(`\nExploit URLs:`);
    vulnerability.exploit_examples_url.forEach((url) => {
      console.log(`  - ${url}`);
    });
    console.log(`\nPublished: ${vulnerability.published_date}`);
    console.log(`Updated: ${vulnerability.updated_date}`);
  });

// Validate command (for testing rule structure)
program
  .command('validate <file>')
  .description('Validate a WAF rule JSON file')
  .action(async (file: string) => {
    try {
      const { readFile } = await import('fs/promises');
      const content = await readFile(file, 'utf-8');
      const rule = JSON.parse(content);

      const { WafRuleSchema } = await import('./schemas/waf-rule.js');
      const { validateRuleStructure } = await import('./validation/semantic.js');

      // Schema validation
      const schemaResult = WafRuleSchema.safeParse(rule);
      if (!schemaResult.success) {
        console.error('\nSchema validation failed:');
        schemaResult.error.errors.forEach((err) => {
          console.error(`  - ${err.path.join('.')}: ${err.message}`);
        });
        process.exit(1);
      }

      // Semantic validation
      const semanticResult = validateRuleStructure(schemaResult.data);

      console.log('\n--- Validation Results ---\n');
      console.log(`Schema: ✓ Valid`);
      console.log(`Semantic: ${semanticResult.valid ? '✓ Valid' : '✗ Invalid'}`);

      if (semanticResult.errors.length > 0) {
        console.log('\nErrors:');
        semanticResult.errors.forEach((err) => console.log(`  ✗ ${err}`));
      }

      if (semanticResult.warnings.length > 0) {
        console.log('\nWarnings:');
        semanticResult.warnings.forEach((warn) => console.log(`  ⚠ ${warn}`));
      }

      process.exit(semanticResult.valid ? 0 : 1);
    } catch (error) {
      console.error('Error:', error instanceof Error ? error.message : error);
      process.exit(1);
    }
  });

// Parse and run
program.parse();
