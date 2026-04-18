export declare function pathExists(target: string): Promise<boolean>;
export declare function readTextIfExists(target: string): Promise<string | undefined>;
export declare function listFiles(rootDir: string): Promise<string[]>;
export declare function relative(rootDir: string, filePath: string): string;
export declare function readJsonFile<T>(target: string): Promise<T | undefined>;
export declare function ensureDirectory(target: string): Promise<void>;
export declare function writeText(target: string, value: string): Promise<void>;
