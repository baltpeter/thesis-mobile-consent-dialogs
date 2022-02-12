import { execa } from 'execa';

// Adapted after: https://stackoverflow.com/a/28573364
export const adb_get_foreground_app_id = async () => {
    const { stdout } = await execa('adb', ['shell', 'dumpsys', 'activity', 'recents']);
    const foreground_line = stdout.split('\n').find((l) => l.includes('Recent #0'));
    const [, app_id] = foreground_line.match(/A=\d+:(.+?) U=/) || '';
    return app_id ? app_id.trim() : undefined;
};

export const adb_get_pid_for_app_id = async (app_id) => {
    const { stdout } = await execa('adb', ['shell', 'pidof', '-s', app_id]);
    return parseInt(stdout, 10);
};

export const android_get_apk_version = async (apk_path) =>
    (await execa('aapt', ['dump', 'badging', apk_path])).stdout.match(/versionName='(.+?)'/)[1];

export const shuffle = (arr) => arr.sort(() => Math.random() - 0.5);
