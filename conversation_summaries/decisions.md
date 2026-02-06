# Key Decisions Made During Planning

## 1. Framework Choice: Native Vercel AI SDK vs Mastra/LangGraph

**Decision**: Use native Vercel AI SDK without additional orchestration frameworks.

**Rationale**: 
- The flow is linear: fetch → enrich → generate → validate → retry
- `generateObject` with Zod provides built-in schema validation and retry
- Mastra/LangGraph would add complexity without clear benefit for this use case

## 2. Exploit URL Enrichment

**Decision**: Fetch and analyze `exploit_examples_url` before generating WAF rules.

**Rationale**:
- CVE descriptions are often vague (e.g., "deserialization vulnerability")
- Exploit articles contain specific endpoints, payloads, and request patterns
- More specific patterns = more accurate WAF rules

**Implementation**:
- Use cheaper model (gpt-4o-mini) for URL content extraction
- Extract structured data: endpoints, HTTP methods, payload signatures, headers
- Gracefully handle fetch failures (timeout, 404, etc.)

## 3. Two-Layer Validation

**Decision**: Schema validation (Zod) + semantic validation (custom checks).

**Rationale**:
- Schema ensures structural correctness (valid JSON, correct field types)
- Semantic checks ensure logical correctness (has Block action, proper transformations)
- Semantic validation can warn about best practices without failing

## 4. Recursive Schema Handling

**Issue**: AWS WAF rules support nested AND/OR/NOT statements (recursive structure).

**Decision**: Use `z.lazy()` for recursive types, accept SDK warnings.

**Result**: Vercel AI SDK shows "Recursive reference detected" warnings but handles it gracefully by falling back to untyped validation for nested parts.

## 5. Multi-Provider Support

**Decision**: Support OpenAI, Anthropic, and Google via Vercel AI SDK's provider abstraction.

**Implementation**:
- Provider selection via `LLM_PROVIDER` environment variable
- Each provider has `main` (gpt-4o/claude-sonnet/gemini-pro) and `mini` (cheaper) models
- Seamless switching without code changes
