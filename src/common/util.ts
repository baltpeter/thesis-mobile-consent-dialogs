import { ExecaChildProcess } from 'execa';
import { timeout } from 'promise-timeout';

export const shuffle = <T>(arr: T[]) => arr.sort(() => Math.random() - 0.5);

export const base64_decode = (base64: string) => Buffer.from(base64, 'base64').toString();

export const str2bool = (val?: string | boolean) => {
    if (typeof val === 'boolean' || val === undefined) return val;
    return ['true', 'yes', '1', 'y', 't'].includes(val.toLowerCase());
};

export const concat = (...strs: (string | undefined | (string | undefined)[])[]) =>
    strs
        .filter((s) => s)
        .filter((s) => !Array.isArray(s) || s.every((s) => s))
        .map((s) => (Array.isArray(s) ? `(${s.join(' ')})` : s))
        .join(' ') || undefined;

export const pause = (duration_in_ms: number) => new Promise((res) => setTimeout(res, duration_in_ms));

export const await_proc_start = (proc: ExecaChildProcess<string>, start_message: string) => {
    return new Promise<true>((res) => {
        proc.stdout?.addListener('data', (chunk: string) => {
            if (chunk.includes(start_message)) {
                proc.stdout?.removeAllListeners('data');
                res(true);
            }
        });
    });
};
export const kill_process = async (proc?: ExecaChildProcess) => {
    if (proc) {
        proc.kill();
        await timeout(proc, 5000).catch(() => proc.kill(9));
    }
};

type SortType = `${'key' | 'value'}_${'asc' | 'desc'}`;
type SortFunction = <ValT extends string | number>(a: [string, ValT], b: [string, ValT]) => number;
export const obj_sort = <T extends Record<string, string> | Record<string, number>>(
    obj: T,
    sort_by: SortType | SortFunction
) => {
    const sort_by_functions: Record<SortType, SortFunction> = {
        // @ts-ignore
        value_asc: ([, a], [, b]) => (typeof a === 'string' ? a.localeCompare(b) : a - b),
        key_asc: ([a], [b]) => a.localeCompare(b),
        // @ts-ignore
        value_desc: ([, a], [, b]) => (typeof a === 'string' ? b.localeCompare(a) : b - a),
        key_desc: ([a], [b]) => b.localeCompare(a),
    };
    return Object.fromEntries(
        Object.entries(obj).sort(typeof sort_by === 'string' ? sort_by_functions[sort_by] : sort_by)
    ) as T;
};
