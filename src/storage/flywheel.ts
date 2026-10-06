import { DatabaseSync } from 'node:sqlite';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { SwarmSimulationRequest, SwarmSimulationResult } from '../swarm/types.js';
import {
  RuleEnhancementRecord,
  FlywheelStats,
  SimulationRecord,
  AttackVectorRecord,
  AuditEventRecord
} from './types.js';

export {
  RuleEnhancementRecord,
  FlywheelStats,
  SimulationRecord,
  AttackVectorRecord,
  AuditEventRecord
};

export class DataFlywheel {
  private db: DatabaseSync;
  private dbPath: string;

  constructor(dbPath?: string) {
    this.dbPath =
      dbPath ??
      process.env.BLAST_RADIUS_FLYWHEEL_PATH ??
      path.join(process.cwd(), '.blastradius', 'flywheel.db');

    if (this.dbPath !== ':memory:') {
      const dir = path.dirname(this.dbPath);
      try {
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
      } catch {
        // Fall back gracefully if directory creation fails
        this.dbPath = ':memory:';
      }
    }

    try {
      this.db = new DatabaseSync(this.dbPath, { timeout: 5000 });
    } catch {
      this.dbPath = ':memory:';
      this.db = new DatabaseSync(':memory:', { timeout: 5000 });
    }
    this.initSchema();
  }

  private initSchema(): void {
    try {
      this.db.exec('PRAGMA busy_timeout = 5000;');
      if (this.dbPath !== ':memory:') {
        this.db.exec('PRAGMA journal_mode = WAL;');
      }
    } catch {
      // Pragmas may fail or be ignored on some setups; proceed safely
    }

    this.db.exec(`
      CREATE TABLE IF NOT EXISTS simulation_records (
        id TEXT PRIMARY KEY,
        target_diff TEXT,
        context_desc TEXT,
        risk_score REAL,
        verdict TEXT,
        personas_count INTEGER,
        divergence REAL,
        created_at TEXT
      );

      CREATE TABLE IF NOT EXISTS attack_vectors (
        id TEXT PRIMARY KEY,
        simulation_id TEXT,
        persona_type TEXT,
        attack_vector TEXT,
        severity TEXT,
        description TEXT,
        suggested_test TEXT,
        reproduction_steps TEXT,
        created_at TEXT
      );

      CREATE TABLE IF NOT EXISTS rule_enhancements (
        id TEXT PRIMARY KEY,
        vector_id TEXT,
        generated_rule_id TEXT,
        name TEXT,
        forbidden_pattern TEXT,
        action TEXT,
        status TEXT,
        created_at TEXT
      );

      CREATE TABLE IF NOT EXISTS audit_events (
        id TEXT PRIMARY KEY,
        tool_name TEXT,
        caller_id TEXT,
        decision TEXT,
        risk_score REAL,
        hash TEXT,
        created_at TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_attack_vectors_sim ON attack_vectors(simulation_id);
      CREATE INDEX IF NOT EXISTS idx_attack_vectors_vec ON attack_vectors(attack_vector);
      CREATE INDEX IF NOT EXISTS idx_rule_enhancements_status ON rule_enhancements(status);
    `);
  }

  public recordSimulation(result: SwarmSimulationResult, request: SwarmSimulationRequest): void {
    this.db.exec('BEGIN IMMEDIATE;');
    try {
      const insertSim = this.db.prepare(`
        INSERT INTO simulation_records (
          id, target_diff, context_desc, risk_score, verdict, personas_count, divergence, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const simCreatedAt = result.timestamp ?? new Date().toISOString();
      insertSim.run(
        result.simulationId,
        request.targetDiffOrCommand,
        request.contextDescription ?? '',
        result.prRiskScore,
        result.verdict,
        result.personasSimulated,
        result.divergenceFromStatic,
        simCreatedAt
      );

      const insertVector = this.db.prepare(`
        INSERT INTO attack_vectors (
          id, simulation_id, persona_type, attack_vector, severity, description, suggested_test, reproduction_steps, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      const insertEnhancement = this.db.prepare(`
        INSERT INTO rule_enhancements (
          id, vector_id, generated_rule_id, name, forbidden_pattern, action, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);

      for (const finding of result.criticalFindings ?? []) {
        const vectorId = crypto.randomUUID();
        const reproSteps = Array.isArray(finding.reproductionSteps)
          ? JSON.stringify(finding.reproductionSteps)
          : (finding.reproductionSteps ?? '');
        const createdAt = new Date().toISOString();

        insertVector.run(
          vectorId,
          result.simulationId,
          finding.personaType,
          finding.attackVector,
          finding.severity,
          finding.description,
          finding.suggestedTest ?? '',
          reproSteps,
          createdAt
        );

        if (finding.severity === 'HIGH' || finding.severity === 'CRITICAL') {
          const enhancementId = crypto.randomUUID();
          const slug = finding.attackVector
            .toLowerCase()
            .replace(/[^a-z0-9]+/g, '_')
            .replace(/^_+|_+$/g, '')
            .slice(0, 30);
          const generatedRuleId = `auto_${slug}_${crypto.randomBytes(4).toString('hex')}`;
          const name = `Auto-Mitigation for ${finding.attackVector}`;
          // Clean, normalized pattern compatible with PolicyEngine substring matching
          const forbiddenPattern = finding.attackVector.toLowerCase();
          const action = 'BLOCK';
          const status = 'PENDING';

          insertEnhancement.run(
            enhancementId,
            vectorId,
            generatedRuleId,
            name,
            forbiddenPattern,
            action,
            status,
            createdAt
          );
        }
      }

      this.db.exec('COMMIT;');
    } catch (err) {
      if (this.db.isTransaction) {
        try {
          this.db.exec('ROLLBACK;');
        } catch {
          // ignore rollback failure
        }
      }
      throw err;
    }
  }

  public getStats(): FlywheelStats {
    const simRow = this.db
      .prepare('SELECT COUNT(*) as count, AVG(risk_score) as avgScore FROM simulation_records')
      .get() as { count?: number | bigint; avgScore?: number | null } | undefined;

    const vectorRow = this.db
      .prepare('SELECT COUNT(*) as count FROM attack_vectors')
      .get() as { count?: number | bigint } | undefined;

    const appliedRow = this.db
      .prepare("SELECT COUNT(*) as count FROM rule_enhancements WHERE status = 'AUTO_APPLIED'")
      .get() as { count?: number | bigint } | undefined;

    const pendingRow = this.db
      .prepare("SELECT COUNT(*) as count FROM rule_enhancements WHERE status = 'PENDING'")
      .get() as { count?: number | bigint } | undefined;

    const topVectorsRows = this.db
      .prepare(
        `SELECT attack_vector as vector, COUNT(*) as count
         FROM attack_vectors
         GROUP BY attack_vector
         ORDER BY count DESC
         LIMIT 10`
      )
      .all() as Array<{ vector: string; count: number | bigint }>;

    const totalSimulations = Number(simRow?.count ?? 0);
    const avgScore = simRow?.avgScore != null ? Number(simRow.avgScore) : 0;
    const averageRiskScore = Math.round(avgScore * 100) / 100;
    const attackVectorsLearned = Number(vectorRow?.count ?? 0);
    const enhancementsApplied = Number(appliedRow?.count ?? 0);
    const pendingEnhancements = Number(pendingRow?.count ?? 0);

    const topAttackVectors = (topVectorsRows ?? []).map(row => ({
      vector: String(row.vector),
      count: Number(row.count)
    }));

    return {
      totalSimulations,
      attackVectorsLearned,
      enhancementsApplied,
      pendingEnhancements,
      averageRiskScore,
      topAttackVectors
    };
  }

  public getPendingEnhancements(): Array<RuleEnhancementRecord> {
    const rows = this.db
      .prepare(
        `SELECT id, vector_id as vectorId, generated_rule_id as generatedRuleId, name,
                forbidden_pattern as forbiddenPattern, action, status, created_at as createdAt
         FROM rule_enhancements
         WHERE status = 'PENDING'
         ORDER BY created_at ASC`
      )
      .all() as unknown as Array<{
        id: string;
        vectorId: string;
        generatedRuleId: string;
        name: string;
        forbiddenPattern: string;
        action: string;
        status: string;
        createdAt: string;
      }>;

    return (rows ?? []).map(r => ({
      id: String(r.id),
      vectorId: String(r.vectorId),
      generatedRuleId: String(r.generatedRuleId),
      name: String(r.name),
      forbiddenPattern: String(r.forbiddenPattern),
      action: String(r.action),
      status: r.status,
      createdAt: String(r.createdAt)
    }));
  }

  public applyEnhancement(id: string): boolean {
    const stmt = this.db.prepare("UPDATE rule_enhancements SET status = 'AUTO_APPLIED' WHERE id = ?");
    const result = stmt.run(id);
    return Number(result.changes) > 0;
  }

  public recordAuditEvent(event: {
    toolName: string;
    callerId: string;
    decision: string;
    riskScore: number;
    hash: string;
  }): void {
    const stmt = this.db.prepare(`
      INSERT INTO audit_events (id, tool_name, caller_id, decision, risk_score, hash, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);
    stmt.run(
      crypto.randomUUID(),
      event.toolName,
      event.callerId,
      event.decision,
      event.riskScore,
      event.hash,
      new Date().toISOString()
    );
  }

  public close(): void {
    try {
      if (this.db && this.db.isOpen) {
        this.db.close();
      }
    } catch {
      // Ignore if already closed
    }
  }
}

// Lazy singleton initialization to avoid lock contention during module loading across parallel workers
let _singletonInstance: DataFlywheel | null = null;
function getSingleton(): DataFlywheel {
  if (!_singletonInstance) {
    _singletonInstance = new DataFlywheel();
  }
  return _singletonInstance;
}

export const dataFlywheel: DataFlywheel = new Proxy({} as DataFlywheel, {
  get(_target, prop, receiver) {
    const instance = getSingleton();
    const value = Reflect.get(instance, prop, receiver);
    if (typeof value === 'function') {
      return value.bind(instance);
    }
    return value;
  },
  getPrototypeOf() {
    return DataFlywheel.prototype;
  }
});
