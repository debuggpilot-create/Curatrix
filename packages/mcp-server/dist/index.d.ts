export declare function runCuratrixScanTool({ path: targetPath, format, }: {
    path?: string;
    format?: "json" | "text";
}): Promise<{
    content: {
        type: "text";
        text: string;
    }[];
    isError: boolean;
} | {
    content: {
        type: "text";
        text: string;
    }[];
    isError?: undefined;
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
