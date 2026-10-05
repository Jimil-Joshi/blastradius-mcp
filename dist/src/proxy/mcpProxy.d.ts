export declare class MCPProxyGateway {
    private downstreamCmd;
    private downstreamArgs;
    private childProcess?;
    private policyEngine;
    constructor(commandString: string);
    start(): void;
    private handleClientLine;
    private handleDownstreamLine;
}
