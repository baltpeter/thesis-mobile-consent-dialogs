import { execa } from 'execa';

// Adapted after: https://stackoverflow.com/a/28573364
export const adb_get_foreground_app_id = async () => {
    const { stdout } = await execa('adb', ['shell', 'dumpsys', 'activity', 'recents']);
    const foreground_line = stdout.split('\n').find((l) => l.includes('Recent #0'));
    const [, app_id] = Array.from(foreground_line?.match(/A=\d+:(.+?) U=/) || []);
    return app_id ? app_id.trim() : undefined;
};

export const adb_get_pid_for_app_id = async (app_id: string) => {
    const { stdout } = await execa('adb', ['shell', 'pidof', '-s', app_id]);
    return parseInt(stdout, 10);
};

export const android_get_apk_version = async (apk_path: string) =>
    // These sometimes fail with `AndroidManifest.xml:42: error: ERROR getting 'android:icon' attribute: attribute value
    // reference does not exist` but still have the correct version in the output.
    (await execa('aapt', ['dump', 'badging', apk_path], { reject: false })).stdout.match(/versionName='(.+?)'/)?.[1];

export const shuffle = <T>(arr: T[]) => arr.sort(() => Math.random() - 0.5);

export const base64_decode = (base64: string) => Buffer.from(base64, 'base64').toString();

export const str2bool = (val?: string | boolean) => {
    if (typeof val === 'boolean') return val;
    return typeof val === 'string' && ['true', 'yes', '1', 'y', 't'].includes(val.toLowerCase());
};

export const concat = (...strs: (string | undefined | (string | undefined)[])[]) =>
    strs
        .filter((s) => s)
        .filter((s) => !Array.isArray(s) || s.every((s) => s))
        .map((s) => (Array.isArray(s) ? `(${s.join(' ')})` : s))
        .join(' ');
