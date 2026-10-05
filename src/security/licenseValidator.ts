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

export class LicenseValidator {
  private static cachedStatus?: LicenseStatus;

  public static getStatus(): LicenseStatus {
    if (this.cachedStatus) return this.cachedStatus;

    const licenseKey = process.env.BLAST_RADIUS_LICENSE_KEY || '';

    if (licenseKey.startsWith('ENT-') && licenseKey.length >= 24) {
      this.cachedStatus = {
        tier: LicenseTier.ENTERPRISE,
        valid: true,
        owner: 'Enterprise Licensed Organization',
        features: {
          maxInvocationsPerHour: Infinity,
          customPolicies: true,
          cryptographicAudit: true,
          x402Micropayments: true,
          enterpriseSiemExport: true
        }
      };
    } else if (licenseKey.startsWith('PRO-') && licenseKey.length >= 20) {
      this.cachedStatus = {
        tier: LicenseTier.PRO,
        valid: true,
        owner: 'Professional Developer Tier',
        features: {
          maxInvocationsPerHour: 50000,
          customPolicies: true,
          cryptographicAudit: true,
          x402Micropayments: true,
          enterpriseSiemExport: false
        }
      };
    } else {
      this.cachedStatus = {
        tier: LicenseTier.COMMUNITY,
        valid: true,
        owner: 'Open Source Community',
        features: {
          maxInvocationsPerHour: 1000,
          customPolicies: false,
          cryptographicAudit: true,
          x402Micropayments: false,
          enterpriseSiemExport: false
        }
      };
    }

    return this.cachedStatus;
  }

  public static resetCache(): void {
    this.cachedStatus = undefined;
  }
}
