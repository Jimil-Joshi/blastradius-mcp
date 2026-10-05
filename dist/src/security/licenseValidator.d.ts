import { LicenseTier } from '../types.js';
export interface LicenseStatus {
    tier: LicenseTier;
    valid: boolean;
    owner?: string;
    features: {
        maxInvocationsPerHour: number;
        customPolicies: boolean;
        cryptographicAudit: boolean;
        x402Micropayments: boolean;
        enterpriseSiemExport: boolean;
    };
}
export declare class LicenseValidator {
    private static cachedStatus?;
    static getStatus(): LicenseStatus;
    static resetCache(): void;
}
