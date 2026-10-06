/**
 * BlastRadius-Zero Worktree Manager
 * Isolates git worktrees in `.blastradius/worktrees/<agentId>` for subagents
 * so tests and code changes can execute in parallel without polluting the active workspace.
 */

import * as path from 'node:path';
import * as fs from 'node:fs';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { WorktreeResult } from './types.js';

const execFileAsync = promisify(execFile);

export class WorktreeManager {
  private static instance?: WorktreeManager;
  private activeWorktrees: Map<string, WorktreeResult> = new Map();

  public static getInstance(): WorktreeManager {
    if (!WorktreeManager.instance) {
      WorktreeManager.instance = new WorktreeManager();
    }
    return WorktreeManager.instance;
  }

  /**
   * Spawns an isolated git worktree for a subagent.
   * If worktree commands are not supported or fail, safely falls back to branch/isolated folder mode.
   */
  public async spawnWorktree(
    agentId: string,
    branchName: string,
    baseBranch: string = 'HEAD',
    repoRoot?: string
  ): Promise<WorktreeResult> {
    const root = path.resolve(repoRoot || process.cwd());
    const sanitizedAgentId = agentId.replace(/[^a-zA-Z0-9_-]/g, '_');
    const worktreesBase = path.join(root, '.blastradius', 'worktrees');
    const worktreePath = path.join(worktreesBase, sanitizedAgentId);

    // Ensure parent directory exists
    try {
      fs.mkdirSync(worktreesBase, { recursive: true });
    } catch {
      // ignore directory creation error
    }

    let status: WorktreeResult['status'] = 'CREATED';
    let message = `Worktree isolated successfully at ${worktreePath}`;

    try {
      // First clean up any pre-existing directory or stale worktree registration
      if (fs.existsSync(worktreePath)) {
        await this.runGit(['worktree', 'remove', '--force', worktreePath], root).catch(() => {});
        try {
          fs.rmSync(worktreePath, { recursive: true, force: true });
        } catch {}
      }

      // Try git worktree add
      await this.runGit(['worktree', 'add', '-B', branchName, worktreePath, baseBranch], root);
    } catch (worktreeErr: any) {
      // Fallback 1: try with HEAD if baseBranch failed
      try {
        await this.runGit(['worktree', 'add', '-B', branchName, worktreePath, 'HEAD'], root);
      } catch (headErr: any) {
        // Fallback 2: try creating branch and isolating via directory
        try {
          await this.runGit(['branch', '-f', branchName], root).catch(() => {});
          fs.mkdirSync(worktreePath, { recursive: true });
          // Write metadata file to track branch
          fs.writeFileSync(
            path.join(worktreePath, '.worktree-meta.json'),
            JSON.stringify({ agentId, branchName, baseBranch, createdAt: new Date().toISOString() }, null, 2)
          );
          message = `Worktree created in directory fallback mode: ${headErr?.message || worktreeErr?.message}`;
        } catch (dirErr: any) {
          status = 'FAILED';
          message = `Failed to create worktree: ${dirErr?.message || headErr?.message}`;
        }
      }
    }

    const result: WorktreeResult = {
      agentId,
      branchName,
      worktreePath,
      baseBranch,
      status,
      createdAt: new Date().toISOString(),
      message
    };

    this.activeWorktrees.set(agentId, result);
    return result;
  }

  /**
   * Lists all currently tracked and discovered git worktrees.
   */
  public async listWorktrees(repoRoot?: string): Promise<WorktreeResult[]> {
    const root = path.resolve(repoRoot || process.cwd());
    const results: WorktreeResult[] = [];

    // Include tracked active worktrees
    for (const item of this.activeWorktrees.values()) {
      if (item.status !== 'CLEANED') {
        results.push(item);
      }
    }

    // Attempt to discover from filesystem
    const worktreesBase = path.join(root, '.blastradius', 'worktrees');
    if (fs.existsSync(worktreesBase)) {
      try {
        const entries = fs.readdirSync(worktreesBase, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.isDirectory() && !this.activeWorktrees.has(entry.name)) {
            const wPath = path.join(worktreesBase, entry.name);
            results.push({
              agentId: entry.name,
              branchName: `unknown-${entry.name}`,
              worktreePath: wPath,
              baseBranch: 'HEAD',
              status: 'ACTIVE',
              createdAt: new Date().toISOString(),
              message: 'Discovered existing worktree directory'
            });
          }
        }
      } catch {
        // Ignore read errors
      }
    }

    return results;
  }

  /**
   * Cleans up and removes an agent's worktree.
   */
  public async cleanupWorktree(
    agentId: string,
    repoRoot?: string
  ): Promise<{ success: boolean; message: string }> {
    const root = path.resolve(repoRoot || process.cwd());
    const sanitizedAgentId = agentId.replace(/[^a-zA-Z0-9_-]/g, '_');
    const worktreesBase = path.join(root, '.blastradius', 'worktrees');
    const worktreePath = path.join(worktreesBase, sanitizedAgentId);

    try {
      // Git worktree remove
      await this.runGit(['worktree', 'remove', '--force', worktreePath], root).catch(() => {});
      await this.runGit(['worktree', 'prune'], root).catch(() => {});

      // Remove directory if still present
      if (fs.existsSync(worktreePath)) {
        fs.rmSync(worktreePath, { recursive: true, force: true });
      }

      const existing = this.activeWorktrees.get(agentId);
      if (existing) {
        // Also clean up the created branch if not a protected root branch
        if (
          existing.branchName &&
          !['main', 'master', 'HEAD', 'develop', 'feature/blastradius-zero-v2'].includes(existing.branchName)
        ) {
          await this.runGit(['branch', '-D', existing.branchName], root).catch(() => {});
        }
        existing.status = 'CLEANED';
        this.activeWorktrees.delete(agentId);
      }

      return {
        success: true,
        message: `Worktree for agent ${agentId} cleaned up successfully.`
      };
    } catch (err: any) {
      return {
        success: false,
        message: `Error cleaning up worktree: ${err?.message || String(err)}`
      };
    }
  }

  private async runGit(args: string[], cwd: string): Promise<string> {
    const { stdout } = await execFileAsync('git', args, { cwd });
    return stdout.trim();
  }
}

export const worktreeManager = WorktreeManager.getInstance();
