/**
 * BlastRadius-Zero Gateway Types
 * Zero-Bloat context routing and virtualization interfaces
 */

export interface RouteToolParams {
  intent: string;
  candidateServer?: string;
  executeImmediately?: boolean;
  toolArguments?: Record<string, any>;
}

export interface RegisteredToolSchema {
  name: string;
  description: string;
  serverName?: string;
  server?: string;
  inputSchema: Record<string, any>;
  parameters?: Record<string, any>;
  keywords?: string[];
  category?: string;
  tags?: string[];
  examples?: string[];
  handler?: (args: Record<string, any>) => Promise<any> | any;
}

export interface RouteToolResult {
  matchedTool: string;
  confidence: number;
  serverName?: string;
  server?: string;
  schema?: RegisteredToolSchema | Record<string, any>;
  executed: boolean;
  executionResult?: any;
  result?: any;
  reasoning?: string;
  tokensSaved?: number;
  tokenSavingsEstimated?: number;
  tokenReductionPercentage?: number;
  suggestedCall?: {
    tool: string;
    arguments: Record<string, any>;
  };
}

export interface VirtualizeContextParams {
  rawContent: string;
  label?: string;
  retentionTtlSeconds?: number;
}

export interface VirtualContextHandle {
  handleId: string;
  label: string;
  byteSize?: number;
  originalBytes?: number;
  preview?: string;
  previewSnippet?: string;
  tokensEstimated?: number;
  estimatedTokens?: number;
  tokensSaved?: number;
  tokenReductionPercentage?: number;
  retentionTtlSeconds?: number;
  createdAt: string;
  expiresAt: string;
  metadata?: Record<string, any>;
}

export interface SandboxExecutionResult {
  success: boolean;
  result?: any;
  securityVerdict: string;
  reason?: string;
}

