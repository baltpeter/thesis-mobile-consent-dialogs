import { ExecaChildProcess } from 'execa';

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
