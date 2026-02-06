import { describe, it, expect } from 'vitest';
import { validateRuleSemantics, validateRuleStructure } from '../src/validation/semantic.js';
import type { WafRule } from '../src/schemas/waf-rule.js';
import type { VulnerabilityRecord } from '../src/db/vulnerabilities.js';

const mockVulnerability: VulnerabilityRecord = {
  cve_id: 'CVE-2025-12345',
  title: 'Test Vulnerability',
  processed_title: 'Test Vuln',
  severity: 'critical',
  description: 'A test vulnerability for testing purposes.',
  vendor: 'TestVendor',
  product: 'TestProduct',
  cpes: ['cpe:2.3:a:testvendor:testproduct:*:*:*:*:*:*:*:*'],
  exploit_examples_url: ['https://example.com/exploit'],
  published_date: '2025-01-01T00:00:00Z',
  updated_date: '2025-01-02T00:00:00Z',
  vulnerability_date: '2025-01-01 12:00:00',
};

const validRule: WafRule = {
  Name: 'Block-CVE-2025-12345',
  Priority: 1,
  Statement: {
    ByteMatchStatement: {
      SearchString: '/vulnerable/endpoint',
      FieldToMatch: { UriPath: {} },
      TextTransformations: [
        { Priority: 0, Type: 'URL_DECODE' },
        { Priority: 1, Type: 'LOWERCASE' },
      ],
      PositionalConstraint: 'CONTAINS',
    },
  },
  Action: { Block: {} },
  VisibilityConfig: {
    SampledRequestsEnabled: true,
    CloudWatchMetricsEnabled: true,
    MetricName: 'BlockCVE2025_12345',
  },
};

describe('Semantic Validation', () => {
  describe('validateRuleSemantics', () => {
    it('should pass for a well-formed rule', async () => {
      const result = await validateRuleSemantics(validRule, mockVulnerability);
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });

    it('should warn if rule name does not reference CVE', async () => {
      const rule: WafRule = {
        ...validRule,
        Name: 'SomeGenericRule',
      };

      const result = await validateRuleSemantics(rule, mockVulnerability);
      expect(result.valid).toBe(true);
      expect(result.warnings.some(w => w.includes('CVE ID'))).toBe(true);
    });

    it('should fail if rule has no blocking action', async () => {
      const rule: WafRule = {
        ...validRule,
        Action: { Allow: {} },
      };

      const result = await validateRuleSemantics(rule, mockVulnerability);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('Block'))).toBe(true);
    });

    it('should pass if rule has Captcha action', async () => {
      const rule: WafRule = {
        ...validRule,
        Action: { Captcha: {} },
      };

      const result = await validateRuleSemantics(rule, mockVulnerability);
      expect(result.valid).toBe(true);
    });

    it('should warn if CloudWatch metrics disabled', async () => {
      const rule: WafRule = {
        ...validRule,
        VisibilityConfig: {
          ...validRule.VisibilityConfig,
          CloudWatchMetricsEnabled: false,
        },
      };

      const result = await validateRuleSemantics(rule, mockVulnerability);
      expect(result.warnings.some(w => w.includes('CloudWatch'))).toBe(true);
    });

    it('should warn if sampled requests disabled', async () => {
      const rule: WafRule = {
        ...validRule,
        VisibilityConfig: {
          ...validRule.VisibilityConfig,
          SampledRequestsEnabled: false,
        },
      };

      const result = await validateRuleSemantics(rule, mockVulnerability);
      expect(result.warnings.some(w => w.includes('Sampled'))).toBe(true);
    });

    it('should warn about very high priority', async () => {
      const rule: WafRule = {
        ...validRule,
        Priority: 5000,
      };

      const result = await validateRuleSemantics(rule, mockVulnerability);
      expect(result.warnings.some(w => w.includes('Priority'))).toBe(true);
    });
  });

  describe('validateRuleStructure', () => {
    it('should validate a complete rule structure', () => {
      const result = validateRuleStructure(validRule);
      expect(result.valid).toBe(true);
    });

    it('should fail for empty ByteMatch search string', () => {
      const rule: WafRule = {
        ...validRule,
        Statement: {
          ByteMatchStatement: {
            SearchString: '',
            FieldToMatch: { UriPath: {} },
            TextTransformations: [{ Priority: 0, Type: 'NONE' }],
            PositionalConstraint: 'CONTAINS',
          },
        },
      };

      const result = validateRuleStructure(rule);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('empty'))).toBe(true);
    });

    it('should warn about very short search strings', () => {
      const rule: WafRule = {
        ...validRule,
        Statement: {
          ByteMatchStatement: {
            SearchString: 'ab',
            FieldToMatch: { UriPath: {} },
            TextTransformations: [{ Priority: 0, Type: 'NONE' }],
            PositionalConstraint: 'CONTAINS',
          },
        },
      };

      const result = validateRuleStructure(rule);
      expect(result.warnings.some(w => w.includes('short'))).toBe(true);
    });

    it('should fail for empty text transformations', () => {
      const rule: WafRule = {
        ...validRule,
        Statement: {
          ByteMatchStatement: {
            SearchString: '/test/',
            FieldToMatch: { UriPath: {} },
            TextTransformations: [],
            PositionalConstraint: 'CONTAINS',
          },
        },
      };

      const result = validateRuleStructure(rule);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('TextTransformation'))).toBe(true);
    });

    it('should validate AND statements with multiple conditions', () => {
      const rule: WafRule = {
        ...validRule,
        Statement: {
          AndStatement: {
            Statements: [
              {
                ByteMatchStatement: {
                  SearchString: '/api/',
                  FieldToMatch: { UriPath: {} },
                  TextTransformations: [{ Priority: 0, Type: 'NONE' }],
                  PositionalConstraint: 'CONTAINS',
                },
              },
              {
                ByteMatchStatement: {
                  SearchString: 'POST',
                  FieldToMatch: { Method: {} },
                  TextTransformations: [{ Priority: 0, Type: 'NONE' }],
                  PositionalConstraint: 'EXACTLY',
                },
              },
            ],
          },
        },
      };

      const result = validateRuleStructure(rule);
      expect(result.valid).toBe(true);
    });

    it('should fail AND statements with single condition', () => {
      const rule: WafRule = {
        ...validRule,
        Statement: {
          AndStatement: {
            Statements: [
              {
                ByteMatchStatement: {
                  SearchString: '/api/',
                  FieldToMatch: { UriPath: {} },
                  TextTransformations: [{ Priority: 0, Type: 'NONE' }],
                  PositionalConstraint: 'CONTAINS',
                },
              },
            ],
          },
        },
      };

      const result = validateRuleStructure(rule);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('2 statements'))).toBe(true);
    });

    it('should fail for invalid regex patterns', () => {
      const rule: WafRule = {
        ...validRule,
        Statement: {
          RegexMatchStatement: {
            RegexString: '[invalid(regex',
            FieldToMatch: { Body: { OversizeHandling: 'CONTINUE' } },
            TextTransformations: [{ Priority: 0, Type: 'NONE' }],
          },
        },
      };

      const result = validateRuleStructure(rule);
      expect(result.valid).toBe(false);
      expect(result.errors.some(e => e.includes('invalid regex'))).toBe(true);
    });
  });
});
