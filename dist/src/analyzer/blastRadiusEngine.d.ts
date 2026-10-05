import { ActionCategory, BlastRadiusReport } from '../types.js';
export declare class BlastRadiusEngine {
    /**
     * Automatically detect the category of an action if not explicitly provided.
     */
    static inferCategory(content: string): ActionCategory;
    /**
     * Evaluates blast radius, danger score, and generates a simulation report.
     */
    static evaluate(commandOrQuery: string, explicitCategory?: ActionCategory, context?: Record<string, any>): BlastRadiusReport;
    private static extractAffectedTargets;
}
