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
  inputSchema: Record<string, any>;
  keywords?: string[];
  category?: string;
  tags?: string[];
}

export interface RouteToolResult {
  matchedTool: string;
  confidence: number;
  serverName?: string;
  schema?: RegisteredToolSchema | Record<string, any>;
  executed: boolean;
  executionResult?: any;
  reasoning?: string;
  tokensSaved?: number;
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
  originalBytes: number;
  preview: string;
  tokensEstimated: number;
  tokensSaved: number;
  retentionTtlSeconds: number;
  createdAt: string;
  expiresAt: string;
  metadata?: Record<string, any>;
}
