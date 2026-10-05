import { SeverityLevel } from '../types.js';
const DLP_PATTERNS = [
    // --- CREDENTIALS & SECRETS ---
    {
        type: 'AWS_ACCESS_KEY',
        category: 'CREDENTIAL',
        severity: SeverityLevel.CRITICAL,
        pattern: /\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b/g,
        maskPrefix: 'REDACTED_AWS_KEY'
    },
    {
        type: 'GITHUB_PAT',
        category: 'CREDENTIAL',
        severity: SeverityLevel.CRITICAL,
        pattern: /\b(ghp_[0-9a-zA-Z]{30,40}|github_pat_[0-9a-zA-Z_]{70,90})\b/g,
        maskPrefix: 'REDACTED_GITHUB_TOKEN'
    },
    {
        type: 'OPENAI_API_KEY',
        category: 'CREDENTIAL',
        severity: SeverityLevel.CRITICAL,
        pattern: /\bsk-(proj-)?[a-zA-Z0-9_-]{32,64}\b/g,
        maskPrefix: 'REDACTED_OPENAI_KEY'
    },
    {
        type: 'STRIPE_SECRET_KEY',
        category: 'CREDENTIAL',
        severity: SeverityLevel.CRITICAL,
        pattern: /\b(sk_live|rk_live)_[0-9a-zA-Z]{24,34}\b/g,
        maskPrefix: 'REDACTED_STRIPE_KEY'
    },
    {
        type: 'SLACK_TOKEN',
        category: 'CREDENTIAL',
        severity: SeverityLevel.CRITICAL,
        pattern: /\bxox[baprs]-[0-9a-zA-Z-]{10,48}\b/g,
        maskPrefix: 'REDACTED_SLACK_TOKEN'
    },
    {
        type: 'SSH_PRIVATE_KEY',
        category: 'CREDENTIAL',
        severity: SeverityLevel.CRITICAL,
        pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g,
        maskPrefix: 'REDACTED_SSH_PRIVATE_KEY'
    },
    {
        type: 'DATABASE_CONN_URI_PASSWORD',
        category: 'CREDENTIAL',
        severity: SeverityLevel.HIGH,
        pattern: /(postgres|mysql|redis|mongodb|amqp):\/\/[^:\s]+:([^@\s]+)@/g,
        maskPrefix: 'REDACTED_URI_PASSWORD'
    },
    {
        type: 'GENERIC_JWT',
        category: 'SECRET',
        severity: SeverityLevel.HIGH,
        pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
        maskPrefix: 'REDACTED_JWT'
    },
    // --- PII ---
    {
        type: 'CREDIT_CARD_NUMBER',
        category: 'PII',
        severity: SeverityLevel.HIGH,
        pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g,
        maskPrefix: 'REDACTED_CREDIT_CARD'
    },
    {
        type: 'US_SSN',
        category: 'PII',
        severity: SeverityLevel.HIGH,
        pattern: /\b\d{3}-\d{2}-\d{4}\b/g,
        maskPrefix: 'REDACTED_US_SSN'
    },
    {
        type: 'EMAIL_ADDRESS',
        category: 'PII',
        severity: SeverityLevel.MEDIUM,
        pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g,
        maskPrefix: 'REDACTED_EMAIL'
    }
];
export class DLPScanner {
    /**
     * Scans content and returns findings along with masked / redacted string.
     */
    static scan(content, maskSensitive = true) {
        if (!content || typeof content !== 'string') {
            return {
                hasFindings: false,
                findingsCount: 0,
                findings: [],
                sanitizedContent: content || '',
                originalRedactedDiffCount: 0
            };
        }
        const findings = [];
        let sanitized = content;
        for (const def of DLP_PATTERNS) {
            def.pattern.lastIndex = 0;
            let match;
            while ((match = def.pattern.exec(content)) !== null) {
                const rawMatch = match[0];
                const startIndex = match.index;
                const endIndex = startIndex + rawMatch.length;
                // Masked preview e.g. "AKIA...1234"
                const preview = rawMatch.length > 8
                    ? `${rawMatch.slice(0, 4)}...${rawMatch.slice(-4)}`
                    : '[HIDDEN]';
                findings.push({
                    type: def.type,
                    category: def.category,
                    severity: def.severity,
                    preview,
                    startIndex,
                    endIndex
                });
            }
            if (maskSensitive) {
                // Reset lastIndex before running replace
                def.pattern.lastIndex = 0;
                sanitized = sanitized.replace(def.pattern, (matched) => {
                    if (def.type === 'DATABASE_CONN_URI_PASSWORD') {
                        return matched.replace(/:\/\/([^:\s]+):([^@\s]+)@/, '://$1:[REDACTED_PASSWORD]@');
                    }
                    const tail = matched.length > 4 ? matched.slice(-4) : '***';
                    return `[${def.maskPrefix}:${tail}]`;
                });
            }
        }
        return {
            hasFindings: findings.length > 0,
            findingsCount: findings.length,
            findings,
            sanitizedContent: maskSensitive ? sanitized : content,
            originalRedactedDiffCount: content.length - sanitized.length
        };
    }
}
