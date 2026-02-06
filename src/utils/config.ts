import { openai } from '@ai-sdk/openai';
import { anthropic } from '@ai-sdk/anthropic';
import { google } from '@ai-sdk/google';

export type LLMProvider = 'openai' | 'anthropic' | 'google';

const providers = {
  openai: {
    main: () => openai('gpt-4o'),
    mini: () => openai('gpt-4o-mini'),
  },
  anthropic: {
    main: () => anthropic('claude-sonnet-4-20250514'),
    mini: () => anthropic('claude-sonnet-4-20250514'),
  },
  google: {
    main: () => google('gemini-1.5-pro'),
    mini: () => google('gemini-1.5-flash'),
  },
} as const;

export function getProvider(): LLMProvider {
  const provider = process.env.LLM_PROVIDER as LLMProvider | undefined;
  if (provider && provider in providers) {
    return provider;
  }
  return 'openai';
}

export function getModel(type: 'main' | 'mini' = 'main') {
  const provider = getProvider();
  return providers[provider][type]();
}

export function validateEnvironment(): void {
  const provider = getProvider();
  
  const requiredKeys: Record<LLMProvider, string> = {
    openai: 'OPENAI_API_KEY',
    anthropic: 'ANTHROPIC_API_KEY',
    google: 'GOOGLE_GENERATIVE_AI_API_KEY',
  };

  const key = requiredKeys[provider];
  if (!process.env[key]) {
    throw new Error(
      `Missing ${key} environment variable. Set it in your .env file or environment.`
    );
  }
}
