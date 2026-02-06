import type { WafRule, Statement } from '../schemas/waf-rule.js';
import type { VulnerabilityRecord } from '../db/vulnerabilities.js';

export interface ValidationResult {
  valid: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Validate the semantic correctness of a WAF rule
 * This goes beyond schema validation to check logical correctness
 */
export async function validateRuleSemantics(
  rule: WafRule,
  vulnerability: VulnerabilityRecord
): Promise<ValidationResult> {
  const errors: string[] = [];
  const warnings: string[] = [];

  // Check 1: Rule name should reference the CVE
  const cveNumber = vulnerability.cve_id.replace('CVE-', '').replace(/-/g, '_');
  if (!rule.Name.toLowerCase().includes(cveNumber.toLowerCase()) &&
      !rule.Name.toLowerCase().includes(vulnerability.cve_id.toLowerCase().replace(/-/g, '_'))) {
    warnings.push(`Rule name "${rule.Name}" should reference CVE ID for traceability`);
  }

  // Check 2: Must have a blocking action for security rules
  if (!rule.Action.Block && !rule.Action.Captcha && !rule.Action.Challenge) {
    errors.push('Security rule must have Block, Captcha, or Challenge action');
  }

  // Check 3: MetricName should be valid
  if (rule.VisibilityConfig.MetricName.length === 0) {
    errors.push('MetricName cannot be empty');
  }

  // Check 4: Statement must have at least one match condition
  const statementValidation = validateStatement(rule.Statement);
  if (!statementValidation.hasMatchCondition) {
    errors.push('Rule statement must have at least one match condition');
  }
  errors.push(...statementValidation.errors);
  warnings.push(...statementValidation.warnings);

  // Check 5: Priority should be reasonable
  if (rule.Priority > 1000) {
    warnings.push(`Priority ${rule.Priority} is very high - consider lower values for exploit blocking rules`);
  }

  // Check 6: CloudWatch metrics should be enabled for monitoring
  if (!rule.VisibilityConfig.CloudWatchMetricsEnabled) {
    warnings.push('CloudWatch metrics should be enabled for production rules');
  }

  // Check 7: Sampled requests should be enabled for debugging
  if (!rule.VisibilityConfig.SampledRequestsEnabled) {
    warnings.push('Sampled requests should be enabled for debugging blocked requests');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}

interface StatementValidation {
  hasMatchCondition: boolean;
  errors: string[];
  warnings: string[];
}

/**
 * Recursively validate a statement and its nested statements
 */
function validateStatement(statement: Statement): StatementValidation {
  const errors: string[] = [];
  const warnings: string[] = [];
  let hasMatchCondition = false;

  // Check for basic match conditions
  if (statement.ByteMatchStatement) {
    hasMatchCondition = true;
    validateByteMatch(statement.ByteMatchStatement, errors, warnings);
  }

  if (statement.RegexMatchStatement) {
    hasMatchCondition = true;
    validateRegexMatch(statement.RegexMatchStatement, errors, warnings);
  }

  if (statement.SqliMatchStatement) {
    hasMatchCondition = true;
    // SQLi match is self-contained
  }

  if (statement.XssMatchStatement) {
    hasMatchCondition = true;
    // XSS match is self-contained
  }

  if (statement.SizeConstraintStatement) {
    hasMatchCondition = true;
  }

  if (statement.GeoMatchStatement) {
    hasMatchCondition = true;
    if (statement.GeoMatchStatement.CountryCodes.length === 0) {
      errors.push('GeoMatchStatement must have at least one country code');
    }
  }

  if (statement.IPSetReferenceStatement) {
    hasMatchCondition = true;
    if (!statement.IPSetReferenceStatement.ARN) {
      errors.push('IPSetReferenceStatement must have a valid ARN');
    }
  }

  if (statement.LabelMatchStatement) {
    hasMatchCondition = true;
  }

  // Check compound statements recursively
  if (statement.AndStatement) {
    if (statement.AndStatement.Statements.length < 2) {
      errors.push('AndStatement must have at least 2 statements');
    }
    for (const subStatement of statement.AndStatement.Statements) {
      const subValidation = validateStatement(subStatement);
      hasMatchCondition = hasMatchCondition || subValidation.hasMatchCondition;
      errors.push(...subValidation.errors);
      warnings.push(...subValidation.warnings);
    }
  }

  if (statement.OrStatement) {
    if (statement.OrStatement.Statements.length < 2) {
      errors.push('OrStatement must have at least 2 statements');
    }
    for (const subStatement of statement.OrStatement.Statements) {
      const subValidation = validateStatement(subStatement);
      hasMatchCondition = hasMatchCondition || subValidation.hasMatchCondition;
      errors.push(...subValidation.errors);
      warnings.push(...subValidation.warnings);
    }
  }

  if (statement.NotStatement) {
    const subValidation = validateStatement(statement.NotStatement.Statement);
    hasMatchCondition = hasMatchCondition || subValidation.hasMatchCondition;
    errors.push(...subValidation.errors);
    warnings.push(...subValidation.warnings);
  }

  return { hasMatchCondition, errors, warnings };
}

/**
 * Validate ByteMatchStatement specifics
 */
function validateByteMatch(
  statement: NonNullable<Statement['ByteMatchStatement']>,
  errors: string[],
  warnings: string[]
): void {
  // SearchString should not be empty
  if (!statement.SearchString || statement.SearchString.length === 0) {
    errors.push('ByteMatchStatement SearchString cannot be empty');
  }

  // SearchString should not be too short (risk of false positives)
  if (statement.SearchString && statement.SearchString.length < 3) {
    warnings.push(`ByteMatchStatement SearchString "${statement.SearchString}" is very short - high false positive risk`);
  }

  // Must have at least one text transformation
  if (!statement.TextTransformations || statement.TextTransformations.length === 0) {
    errors.push('ByteMatchStatement must have at least one TextTransformation');
  }

  // Check for common best practices
  const hasLowercase = statement.TextTransformations?.some(t => t.Type === 'LOWERCASE');
  const hasUrlDecode = statement.TextTransformations?.some(t => t.Type === 'URL_DECODE');
  
  if (!hasLowercase && !hasUrlDecode && statement.TextTransformations?.every(t => t.Type === 'NONE')) {
    warnings.push('Consider adding URL_DECODE or LOWERCASE transformations to handle encoding variations');
  }

  // Validate FieldToMatch has exactly one field specified
  const fieldToMatch = statement.FieldToMatch;
  const specifiedFields = [
    fieldToMatch.UriPath,
    fieldToMatch.QueryString,
    fieldToMatch.Body,
    fieldToMatch.SingleHeader,
    fieldToMatch.SingleQueryArgument,
    fieldToMatch.AllQueryArguments,
    fieldToMatch.Method,
    fieldToMatch.JsonBody,
    fieldToMatch.Headers,
    fieldToMatch.Cookies,
  ].filter(Boolean);

  if (specifiedFields.length === 0) {
    errors.push('ByteMatchStatement FieldToMatch must specify at least one field');
  }
}

/**
 * Validate RegexMatchStatement specifics
 */
function validateRegexMatch(
  statement: NonNullable<Statement['RegexMatchStatement']>,
  errors: string[],
  warnings: string[]
): void {
  // RegexString should not be empty
  if (!statement.RegexString || statement.RegexString.length === 0) {
    errors.push('RegexMatchStatement RegexString cannot be empty');
  }

  // Try to validate regex syntax (basic check)
  try {
    new RegExp(statement.RegexString);
  } catch {
    errors.push(`RegexMatchStatement has invalid regex: ${statement.RegexString}`);
  }

  // Must have at least one text transformation
  if (!statement.TextTransformations || statement.TextTransformations.length === 0) {
    errors.push('RegexMatchStatement must have at least one TextTransformation');
  }

  // Warn about complex regexes (performance concern)
  if (statement.RegexString && statement.RegexString.length > 200) {
    warnings.push('RegexMatchStatement has a complex regex - may impact performance');
  }
}

/**
 * Quick validation without vulnerability context
 */
export function validateRuleStructure(rule: WafRule): ValidationResult {
  const errors: string[] = [];
  const warnings: string[] = [];

  const statementValidation = validateStatement(rule.Statement);
  if (!statementValidation.hasMatchCondition) {
    errors.push('Rule statement must have at least one match condition');
  }
  errors.push(...statementValidation.errors);
  warnings.push(...statementValidation.warnings);

  if (!rule.Action.Block && !rule.Action.Allow && !rule.Action.Count && 
      !rule.Action.Captcha && !rule.Action.Challenge) {
    errors.push('Rule must have exactly one action defined');
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
  };
}
