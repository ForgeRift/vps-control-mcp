export declare const TOOLS: ({
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            process_name?: undefined;
            lines?: undefined;
            file_path?: undefined;
            start_line?: undefined;
            end_line?: undefined;
            pattern?: undefined;
            context_lines?: undefined;
            count?: undefined;
            dry_run?: undefined;
            description?: undefined;
            command?: undefined;
            justification?: undefined;
        };
        required: string[];
    };
} | {
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            process_name: {
                type: string;
                description: string;
            };
            lines: {
                type: string;
                description: string;
            };
            file_path?: undefined;
            start_line?: undefined;
            end_line?: undefined;
            pattern?: undefined;
            context_lines?: undefined;
            count?: undefined;
            dry_run?: undefined;
            description?: undefined;
            command?: undefined;
            justification?: undefined;
        };
        required: string[];
    };
} | {
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            file_path: {
                type: string;
                description: string;
            };
            start_line: {
                type: string;
                description: string;
            };
            end_line: {
                type: string;
                description: string;
            };
            process_name?: undefined;
            lines?: undefined;
            pattern?: undefined;
            context_lines?: undefined;
            count?: undefined;
            dry_run?: undefined;
            description?: undefined;
            command?: undefined;
            justification?: undefined;
        };
        required: string[];
    };
} | {
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            file_path: {
                type: string;
                description: string;
            };
            pattern: {
                type: string;
                description: string;
            };
            context_lines: {
                type: string;
                description: string;
            };
            process_name?: undefined;
            lines?: undefined;
            start_line?: undefined;
            end_line?: undefined;
            count?: undefined;
            dry_run?: undefined;
            description?: undefined;
            command?: undefined;
            justification?: undefined;
        };
        required: string[];
    };
} | {
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            count: {
                type: string;
                description: string;
            };
            process_name?: undefined;
            lines?: undefined;
            file_path?: undefined;
            start_line?: undefined;
            end_line?: undefined;
            pattern?: undefined;
            context_lines?: undefined;
            dry_run?: undefined;
            description?: undefined;
            command?: undefined;
            justification?: undefined;
        };
        required: string[];
    };
} | {
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            dry_run: {
                type: string;
                description: string;
            };
            process_name?: undefined;
            lines?: undefined;
            file_path?: undefined;
            start_line?: undefined;
            end_line?: undefined;
            pattern?: undefined;
            context_lines?: undefined;
            count?: undefined;
            description?: undefined;
            command?: undefined;
            justification?: undefined;
        };
        required: string[];
    };
} | {
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            dry_run: {
                type: string;
                description: string;
            };
            description: {
                type: string;
                description: string;
            };
            process_name?: undefined;
            lines?: undefined;
            file_path?: undefined;
            start_line?: undefined;
            end_line?: undefined;
            pattern?: undefined;
            context_lines?: undefined;
            count?: undefined;
            command?: undefined;
            justification?: undefined;
        };
        required: string[];
    };
} | {
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            process_name: {
                type: string;
                description: string;
            };
            dry_run: {
                type: string;
                description: string;
            };
            lines?: undefined;
            file_path?: undefined;
            start_line?: undefined;
            end_line?: undefined;
            pattern?: undefined;
            context_lines?: undefined;
            count?: undefined;
            description?: undefined;
            command?: undefined;
            justification?: undefined;
        };
        required: string[];
    };
} | {
    name: string;
    description: string;
    inputSchema: {
        type: string;
        properties: {
            command: {
                type: string;
                description: string;
            };
            justification: {
                type: string;
                description: string;
            };
            dry_run: {
                type: string;
                description: string;
            };
            process_name?: undefined;
            lines?: undefined;
            file_path?: undefined;
            start_line?: undefined;
            end_line?: undefined;
            pattern?: undefined;
            context_lines?: undefined;
            count?: undefined;
            description?: undefined;
        };
        required: string[];
    };
})[];
export declare function executeTool(name: string, args: Record<string, unknown>): Promise<string>;
