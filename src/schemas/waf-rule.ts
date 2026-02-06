import { z } from 'zod';

// Text transformation types used in WAF rules
export const TextTransformationType = z.enum([
  'NONE',
  'COMPRESS_WHITE_SPACE',
  'HTML_ENTITY_DECODE',
  'LOWERCASE',
  'CMD_LINE',
  'URL_DECODE',
  'BASE64_DECODE',
  'HEX_DECODE',
  'MD5',
  'REPLACE_COMMENTS',
  'ESCAPE_SEQ_DECODE',
  'SQL_HEX_DECODE',
  'CSS_DECODE',
  'JS_DECODE',
  'NORMALIZE_PATH',
  'NORMALIZE_PATH_WIN',
  'REMOVE_NULLS',
  'REPLACE_NULLS',
  'BASE64_DECODE_EXT',
  'URL_DECODE_UNI',
  'UTF8_TO_UNICODE',
]);

export const TextTransformationSchema = z.object({
  Priority: z.number().int().min(0),
  Type: TextTransformationType,
});

// Positional constraints for byte/regex matching
export const PositionalConstraint = z.enum([
  'EXACTLY',
  'STARTS_WITH',
  'ENDS_WITH',
  'CONTAINS',
  'CONTAINS_WORD',
]);

// Oversize handling for body inspection
export const OversizeHandling = z.enum([
  'CONTINUE',
  'MATCH',
  'NO_MATCH',
]);

// Field to match - what part of the request to inspect
export const FieldToMatchSchema = z.object({
  SingleHeader: z.object({
    Name: z.string(),
  }).optional(),
  SingleQueryArgument: z.object({
    Name: z.string(),
  }).optional(),
  AllQueryArguments: z.object({}).optional(),
  UriPath: z.object({}).optional(),
  QueryString: z.object({}).optional(),
  Body: z.object({
    OversizeHandling: OversizeHandling.optional(),
  }).optional(),
  Method: z.object({}).optional(),
  JsonBody: z.object({
    MatchPattern: z.object({
      All: z.object({}).optional(),
      IncludedPaths: z.array(z.string()).optional(),
    }),
    MatchScope: z.enum(['ALL', 'KEY', 'VALUE']),
    InvalidFallbackBehavior: z.enum(['MATCH', 'NO_MATCH', 'EVALUATE_AS_STRING']).optional(),
    OversizeHandling: OversizeHandling.optional(),
  }).optional(),
  Headers: z.object({
    MatchPattern: z.object({
      All: z.object({}).optional(),
      IncludedHeaders: z.array(z.string()).optional(),
      ExcludedHeaders: z.array(z.string()).optional(),
    }),
    MatchScope: z.enum(['ALL', 'KEY', 'VALUE']),
    OversizeHandling: OversizeHandling,
  }).optional(),
  Cookies: z.object({
    MatchPattern: z.object({
      All: z.object({}).optional(),
      IncludedCookies: z.array(z.string()).optional(),
      ExcludedCookies: z.array(z.string()).optional(),
    }),
    MatchScope: z.enum(['ALL', 'KEY', 'VALUE']),
    OversizeHandling: OversizeHandling,
  }).optional(),
});

// Byte match statement - matches specific byte patterns
export const ByteMatchStatementSchema = z.object({
  SearchString: z.string(),
  FieldToMatch: FieldToMatchSchema,
  TextTransformations: z.array(TextTransformationSchema),
  PositionalConstraint: PositionalConstraint,
});

// Regex match statement
export const RegexMatchStatementSchema = z.object({
  RegexString: z.string(),
  FieldToMatch: FieldToMatchSchema,
  TextTransformations: z.array(TextTransformationSchema),
});

// SQL injection match statement
export const SqliMatchStatementSchema = z.object({
  FieldToMatch: FieldToMatchSchema,
  TextTransformations: z.array(TextTransformationSchema),
  SensitivityLevel: z.enum(['LOW', 'HIGH']).optional(),
});

// XSS match statement
export const XssMatchStatementSchema = z.object({
  FieldToMatch: FieldToMatchSchema,
  TextTransformations: z.array(TextTransformationSchema),
});

// Size constraint statement
export const SizeConstraintStatementSchema = z.object({
  FieldToMatch: FieldToMatchSchema,
  ComparisonOperator: z.enum(['EQ', 'NE', 'LE', 'LT', 'GE', 'GT']),
  Size: z.number().int().min(0),
  TextTransformations: z.array(TextTransformationSchema),
});

// Geo match statement
export const GeoMatchStatementSchema = z.object({
  CountryCodes: z.array(z.string().length(2)),
  ForwardedIPConfig: z.object({
    HeaderName: z.string(),
    FallbackBehavior: z.enum(['MATCH', 'NO_MATCH']),
  }).optional(),
});

// IP set reference statement
export const IPSetReferenceStatementSchema = z.object({
  ARN: z.string(),
  IPSetForwardedIPConfig: z.object({
    HeaderName: z.string(),
    FallbackBehavior: z.enum(['MATCH', 'NO_MATCH']),
    Position: z.enum(['FIRST', 'LAST', 'ANY']),
  }).optional(),
});

// Label match statement
export const LabelMatchStatementSchema = z.object({
  Scope: z.enum(['LABEL', 'NAMESPACE']),
  Key: z.string(),
});

// Forward declaration for recursive types
type StatementType = z.infer<typeof StatementSchema>;

// Base statement schema (non-recursive parts)
const BaseStatementSchema = z.object({
  ByteMatchStatement: ByteMatchStatementSchema.optional(),
  RegexMatchStatement: RegexMatchStatementSchema.optional(),
  SqliMatchStatement: SqliMatchStatementSchema.optional(),
  XssMatchStatement: XssMatchStatementSchema.optional(),
  SizeConstraintStatement: SizeConstraintStatementSchema.optional(),
  GeoMatchStatement: GeoMatchStatementSchema.optional(),
  IPSetReferenceStatement: IPSetReferenceStatementSchema.optional(),
  LabelMatchStatement: LabelMatchStatementSchema.optional(),
});

// Statement schema with recursive AND/OR/NOT logic
export const StatementSchema: z.ZodType<{
  ByteMatchStatement?: z.infer<typeof ByteMatchStatementSchema>;
  RegexMatchStatement?: z.infer<typeof RegexMatchStatementSchema>;
  SqliMatchStatement?: z.infer<typeof SqliMatchStatementSchema>;
  XssMatchStatement?: z.infer<typeof XssMatchStatementSchema>;
  SizeConstraintStatement?: z.infer<typeof SizeConstraintStatementSchema>;
  GeoMatchStatement?: z.infer<typeof GeoMatchStatementSchema>;
  IPSetReferenceStatement?: z.infer<typeof IPSetReferenceStatementSchema>;
  LabelMatchStatement?: z.infer<typeof LabelMatchStatementSchema>;
  AndStatement?: { Statements: StatementType[] };
  OrStatement?: { Statements: StatementType[] };
  NotStatement?: { Statement: StatementType };
}> = BaseStatementSchema.extend({
  AndStatement: z.object({
    Statements: z.lazy(() => z.array(StatementSchema)),
  }).optional(),
  OrStatement: z.object({
    Statements: z.lazy(() => z.array(StatementSchema)),
  }).optional(),
  NotStatement: z.object({
    Statement: z.lazy(() => StatementSchema),
  }).optional(),
});

// Rule action
export const RuleActionSchema = z.object({
  Block: z.object({
    CustomResponse: z.object({
      ResponseCode: z.number().int().min(200).max(599),
      CustomResponseBodyKey: z.string().optional(),
      ResponseHeaders: z.array(z.object({
        Name: z.string(),
        Value: z.string(),
      })).optional(),
    }).optional(),
  }).optional(),
  Allow: z.object({
    CustomRequestHandling: z.object({
      InsertHeaders: z.array(z.object({
        Name: z.string(),
        Value: z.string(),
      })),
    }).optional(),
  }).optional(),
  Count: z.object({
    CustomRequestHandling: z.object({
      InsertHeaders: z.array(z.object({
        Name: z.string(),
        Value: z.string(),
      })),
    }).optional(),
  }).optional(),
  Captcha: z.object({
    CustomRequestHandling: z.object({
      InsertHeaders: z.array(z.object({
        Name: z.string(),
        Value: z.string(),
      })),
    }).optional(),
  }).optional(),
  Challenge: z.object({
    CustomRequestHandling: z.object({
      InsertHeaders: z.array(z.object({
        Name: z.string(),
        Value: z.string(),
      })),
    }).optional(),
  }).optional(),
});

// Visibility config for CloudWatch metrics
export const VisibilityConfigSchema = z.object({
  SampledRequestsEnabled: z.boolean(),
  CloudWatchMetricsEnabled: z.boolean(),
  MetricName: z.string().regex(/^[a-zA-Z0-9_-]+$/),
});

// Complete WAF Rule schema
export const WafRuleSchema = z.object({
  Name: z.string().regex(/^[a-zA-Z0-9_-]+$/, 'Name must contain only alphanumeric characters, hyphens, and underscores'),
  Priority: z.number().int().min(0),
  Statement: StatementSchema,
  Action: RuleActionSchema,
  VisibilityConfig: VisibilityConfigSchema,
  RuleLabels: z.array(z.object({
    Name: z.string(),
  })).optional(),
  CaptchaConfig: z.object({
    ImmunityTimeProperty: z.object({
      ImmunityTime: z.number().int().min(60).max(259200),
    }),
  }).optional(),
  ChallengeConfig: z.object({
    ImmunityTimeProperty: z.object({
      ImmunityTime: z.number().int().min(60).max(259200),
    }),
  }).optional(),
});

// Type exports
export type WafRule = z.infer<typeof WafRuleSchema>;
export type Statement = z.infer<typeof StatementSchema>;
export type RuleAction = z.infer<typeof RuleActionSchema>;
export type FieldToMatch = z.infer<typeof FieldToMatchSchema>;
