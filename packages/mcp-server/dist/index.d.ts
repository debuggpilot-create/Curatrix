#!/usr/bin/env node
export declare function runCuratrixScanTool({ path: targetPath, format, }: {
    path?: string;
    format?: "json" | "text";
}): Promise<{
    content: {
        type: "text";
        text: string;
    }[];
}>;
export declare function runCuratrixFixTool({ path: targetPath, issueIds, autoConfirm, }: {
    path?: string;
    issueIds?: string[];
    autoConfirm?: boolean;
}): Promise<{
    content: {
        type: "text";
        text: string;
    }[];
}>;
