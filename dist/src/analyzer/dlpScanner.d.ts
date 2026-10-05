import { DLPScanResult } from '../types.js';
export declare class DLPScanner {
    /**
     * Scans content and returns findings along with masked / redacted string.
     */
    static scan(content: string, maskSensitive?: boolean): DLPScanResult;
}
