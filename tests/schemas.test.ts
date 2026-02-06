import { describe, it, expect } from 'vitest';
import { WafRuleSchema, StatementSchema } from '../src/schemas/waf-rule.js';

describe('WAF Rule Schema', () => {
  describe('Valid Rules', () => {
    it('should validate a basic ByteMatch rule', () => {
      const rule = {
        Name: 'Block-SharePoint-API',
        Priority: 1,
        Statement: {
          ByteMatchStatement: {
            SearchString: '/_api/web/',
            FieldToMatch: { UriPath: {} },
            TextTransformations: [{ Priority: 0, Type: 'LOWERCASE' }],
            PositionalConstraint: 'CONTAINS',
          },
        },
        Action: { Block: {} },
        VisibilityConfig: {
          SampledRequestsEnabled: true,
          CloudWatchMetricsEnabled: true,
          MetricName: 'BlockSharePointAPI',
        },
      };

      const result = WafRuleSchema.safeParse(rule);
      expect(result.success).toBe(true);
    });

    it('should validate a RegexMatch rule', () => {
      const rule = {
        Name: 'Block-Log4Shell',
        Priority: 0,
        Statement: {
          RegexMatchStatement: {
            RegexString: '\\$\\{jndi:',
            FieldToMatch: { Body: { OversizeHandling: 'CONTINUE' } },
            TextTransformations: [
              { Priority: 0, Type: 'URL_DECODE' },
              { Priority: 1, Type: 'LOWERCASE' },
            ],
          },
        },
        Action: { Block: {} },
        VisibilityConfig: {
          SampledRequestsEnabled: true,
          CloudWatchMetricsEnabled: true,
          MetricName: 'BlockLog4Shell',
        },
      };

      const result = WafRuleSchema.safeParse(rule);
      expect(result.success).toBe(true);
    });

    it('should validate an AND statement rule', () => {
      const rule = {
        Name: 'Block-Confluence-Setup',
        Priority: 5,
        Statement: {
          AndStatement: {
            Statements: [
              {
                ByteMatchStatement: {
                  SearchString: '/setup/',
                  FieldToMatch: { UriPath: {} },
                  TextTransformations: [{ Priority: 0, Type: 'LOWERCASE' }],
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
        Action: { Block: {} },
        VisibilityConfig: {
          SampledRequestsEnabled: true,
          CloudWatchMetricsEnabled: true,
          MetricName: 'BlockConfluenceSetup',
        },
      };

      const result = WafRuleSchema.safeParse(rule);
      expect(result.success).toBe(true);
    });

    it('should validate a rule with custom block response', () => {
      const rule = {
        Name: 'Block-With-Custom-Response',
        Priority: 10,
        Statement: {
          ByteMatchStatement: {
            SearchString: '/admin/',
            FieldToMatch: { UriPath: {} },
            TextTransformations: [{ Priority: 0, Type: 'LOWERCASE' }],
            PositionalConstraint: 'STARTS_WITH',
          },
        },
        Action: {
          Block: {
            CustomResponse: {
              ResponseCode: 403,
              ResponseHeaders: [
                { Name: 'X-Blocked-By', Value: 'WAF' },
              ],
            },
          },
        },
        VisibilityConfig: {
          SampledRequestsEnabled: true,
          CloudWatchMetricsEnabled: true,
          MetricName: 'BlockAdmin',
        },
      };

      const result = WafRuleSchema.safeParse(rule);
      expect(result.success).toBe(true);
    });

    it('should validate a rule with SQLi match', () => {
      const rule = {
        Name: 'Block-SQLi',
        Priority: 2,
        Statement: {
          SqliMatchStatement: {
            FieldToMatch: { QueryString: {} },
            TextTransformations: [
              { Priority: 0, Type: 'URL_DECODE' },
              { Priority: 1, Type: 'HTML_ENTITY_DECODE' },
            ],
            SensitivityLevel: 'HIGH',
          },
        },
        Action: { Block: {} },
        VisibilityConfig: {
          SampledRequestsEnabled: true,
          CloudWatchMetricsEnabled: true,
          MetricName: 'BlockSQLi',
        },
      };

      const result = WafRuleSchema.safeParse(rule);
      expect(result.success).toBe(true);
    });
  });

  describe('Invalid Rules', () => {
    it('should reject rule with invalid name characters', () => {
      const rule = {
        Name: 'Block Rule With Spaces',
        Priority: 1,
        Statement: {
          ByteMatchStatement: {
            SearchString: '/test/',
            FieldToMatch: { UriPath: {} },
            TextTransformations: [{ Priority: 0, Type: 'NONE' }],
            PositionalConstraint: 'CONTAINS',
          },
        },
        Action: { Block: {} },
        VisibilityConfig: {
          SampledRequestsEnabled: true,
          CloudWatchMetricsEnabled: true,
          MetricName: 'Test',
        },
      };

      const result = WafRuleSchema.safeParse(rule);
      expect(result.success).toBe(false);
    });

    it('should reject rule with negative priority', () => {
      const rule = {
        Name: 'TestRule',
        Priority: -1,
        Statement: {
          ByteMatchStatement: {
            SearchString: '/test/',
            FieldToMatch: { UriPath: {} },
            TextTransformations: [{ Priority: 0, Type: 'NONE' }],
            PositionalConstraint: 'CONTAINS',
          },
        },
        Action: { Block: {} },
        VisibilityConfig: {
          SampledRequestsEnabled: true,
          CloudWatchMetricsEnabled: true,
          MetricName: 'Test',
        },
      };

      const result = WafRuleSchema.safeParse(rule);
      expect(result.success).toBe(false);
    });

    it('should reject rule with invalid positional constraint', () => {
      const rule = {
        Name: 'TestRule',
        Priority: 1,
        Statement: {
          ByteMatchStatement: {
            SearchString: '/test/',
            FieldToMatch: { UriPath: {} },
            TextTransformations: [{ Priority: 0, Type: 'NONE' }],
            PositionalConstraint: 'INVALID',
          },
        },
        Action: { Block: {} },
        VisibilityConfig: {
          SampledRequestsEnabled: true,
          CloudWatchMetricsEnabled: true,
          MetricName: 'Test',
        },
      };

      const result = WafRuleSchema.safeParse(rule);
      expect(result.success).toBe(false);
    });
  });
});

describe('Statement Schema', () => {
  it('should validate nested OR statements', () => {
    const statement = {
      OrStatement: {
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
              SearchString: '/admin/',
              FieldToMatch: { UriPath: {} },
              TextTransformations: [{ Priority: 0, Type: 'NONE' }],
              PositionalConstraint: 'CONTAINS',
            },
          },
        ],
      },
    };

    const result = StatementSchema.safeParse(statement);
    expect(result.success).toBe(true);
  });

  it('should validate NOT statement', () => {
    const statement = {
      NotStatement: {
        Statement: {
          GeoMatchStatement: {
            CountryCodes: ['US', 'CA'],
          },
        },
      },
    };

    const result = StatementSchema.safeParse(statement);
    expect(result.success).toBe(true);
  });
});
