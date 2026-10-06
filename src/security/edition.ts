/**
 * BlastRadius is Apache-2.0 licensed and has no paid tier, no license key, and
 * no metered gating. Every capability listed here ships in the open-source build
 * and is not restricted by any key or quota.
 *
 * This module exists so `get_security_posture` can report *what this build can
 * actually do*, which is verified by the test suite, rather than reporting an
 * entitlement level that nothing in the code enforces.
 */
export interface BuildEdition {
  /** Always 'open-source'. There is no commercial build. */
  edition: 'open-source';
  license: 'Apache-2.0';
  /** No key is needed to run any feature. */
  licenseKeyRequired: false;
  /** No artificial rate limit is applied to tool calls. */
  rateLimited: false;
  capabilities: {
    blastRadiusSimulation: boolean;
    dlpScanning: boolean;
    dlpRedaction: boolean;
    zeroTrustPolicyEnforcement: boolean;
    customPolicyFiles: boolean;
    stepUpApprovalTokens: boolean;
    singleUseTokens: boolean;
    hashChainedAuditLedger: boolean;
    auditIntegrityVerification: boolean;
    transparentProxyMode: boolean;
    outboundResponseRedaction: boolean;
  };
}

/**
 * All open-source capabilities are compiled in, so they are reported as enabled
 * unconditionally. Kept as a function rather than a constant so the shape stays
 * in step with the rest of the package.
 */
export function getEdition(): BuildEdition {
  return {
    edition: 'open-source',
    license: 'Apache-2.0',
    licenseKeyRequired: false,
    rateLimited: false,
    capabilities: {
      blastRadiusSimulation: true,
      dlpScanning: true,
      dlpRedaction: true,
      zeroTrustPolicyEnforcement: true,
      customPolicyFiles: true,
      stepUpApprovalTokens: true,
      singleUseTokens: true,
      hashChainedAuditLedger: true,
      auditIntegrityVerification: true,
      transparentProxyMode: true,
      outboundResponseRedaction: true
    }
  };
}
