import { promises as fs } from "node:fs";
import path from "node:path";

const TEXT_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".json", ".yml", ".yaml", ".txt", ".md", ".env", ".sh", ".toml", ".conf", ".ini", ""
]);
const SKIP_DIRS = new Set([".git", "node_modules", "dist", "coverage", ".turbo"]);

export async function pathExists(target: string): Promise<boolean> {
  try {
    await fs.access(target);
    return true;
  } catch {
    return false;
  }
}

export async function readTextIfExists(target: string): Promise<string | undefined> {
  if (!(await pathExists(target))) {
    return undefined;
  }

  return fs.readFile(target, "utf8");
}

export async function listFiles(rootDir: string): Promise<string[]> {
  const results: string[] = [];

  async function walk(current: string): Promise<void> {
    const entries = await fs.readdir(current, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) {
          await walk(fullPath);
        }
        continue;
      }

      if (TEXT_EXTENSIONS.has(path.extname(entry.name).toLowerCase()) || isSpecialTextFile(entry.name)) {
        results.push(fullPath);
      }
    }
  }

  await walk(rootDir);
  return results.sort();
}

function isSpecialTextFile(name: string): boolean {
  return ["Dockerfile", ".gitignore"].includes(name) || name.startsWith("Dockerfile");
}

export function relative(rootDir: string, filePath: string): string {
  const normalized = path.relative(rootDir, filePath).replace(/\\/g, "/");
  return normalized.length === 0 ? "." : normalized;
}

export async function readJsonFile<T>(target: string): Promise<T | undefined> {
  const content = await readTextIfExists(target);
  if (!content) {
    return undefined;
  }
  return JSON.parse(content) as T;
}

export async function ensureDirectory(target: string): Promise<void> {
  await fs.mkdir(target, { recursive: true });
}

export async function writeText(target: string, value: string): Promise<void> {
  await ensureDirectory(path.dirname(target));
  await fs.writeFile(target, value, "utf8");
}
