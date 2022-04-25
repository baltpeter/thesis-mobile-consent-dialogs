import { promisify } from 'util';
import dns from 'dns';
import { ExecaChildProcess } from 'execa';
import { timeout } from 'promise-timeout';

export const shuffle = <T>(arr: T[]) => arr.sort(() => Math.random() - 0.5);

export const base64_decode = (base64: string) => Buffer.from(base64, 'base64').toString();

export const str2bool = (val?: string | boolean) => {
    if (typeof val === 'boolean' || val === undefined) return val;
    return ['true', 'yes', '1', 'y', 't'].includes(val.toString().toLowerCase());
};

export const concat = (...strs: (string | undefined | (string | undefined)[])[]) =>
    strs
        .filter((s) => s)
        .filter((s) => !Array.isArray(s) || s.every((s) => s))
        .map((s) => (Array.isArray(s) ? `(${s.join(' ')})` : s))
        .join(' ') || undefined;

export const pause = (duration_in_ms: number) => new Promise((res) => setTimeout(res, duration_in_ms));

export const dnsLookup = promisify(dns.lookup);

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

// Adapted after: https://stackoverflow.com/a/51458052
export const is_object = (obj: any): obj is {} => obj && (obj as {}).constructor.name === 'Object';

export const is_not_empty = (value: unknown): boolean =>
    value !== null &&
    value !== undefined &&
    !Number.isNaN(value) &&
    (is_object(value) ? Object.keys(value).length > 0 : true) &&
    (Array.isArray(value) ? value.filter((e) => is_not_empty(e)).length > 0 : true) &&
    value !== '';

// Adapted after: https://stackoverflow.com/a/38340730
export const remove_empty = <T extends Parameters<typeof Object.entries>[0]>(obj: T): Partial<T> =>
    Object.fromEntries(
        Object.entries(obj)
            .filter(([_, v]) => is_not_empty(v))
            .map(([k, v]) => [
                k,
                is_object(v) ? remove_empty(v as {}) : Array.isArray(v) ? v.filter((e) => is_not_empty(e)) : v,
            ])
    ) as Partial<T>;

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

export const jsonify_obj_with_sets = (obj: unknown) =>
    JSON.stringify(obj, (_, v) => (v instanceof Set ? [...v].sort() : v), 4);
