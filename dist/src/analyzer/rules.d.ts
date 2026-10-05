import { ActionCategory, SeverityLevel } from '../types.js';
export interface RuleSignature {
    id: string;
    category: ActionCategory;
    pattern: RegExp;
    dangerScore: number;
    severity: SeverityLevel;
    reason: string;
    destructive: boolean;
    irreversible: boolean;
    mitigations: string[];
}
export declare const DANGEROUS_RULES: RuleSignature[];
