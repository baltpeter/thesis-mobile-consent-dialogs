import fs from 'fs-extra';
import { execa } from 'execa';
// @ts-ignore
import _ipaInfo from 'ipa-extract-info';
import frida from 'frida';
import { pause } from './util.js';

type PlatformApi = {
    ensure_frida: () => Promise<void>;

    install_app: (app_path: string) => Promise<unknown>;
    uninstall_app: (app_id: string) => Promise<unknown>;

    get_foreground_app_id: () => Promise<string | undefined>;
    get_pid_for_app_id: (app_id: string) => Promise<number | undefined>;
    get_prefs: (app_id: string) => Promise<Record<string, unknown> | undefined>;

    get_app_version: (app_path: string) => Promise<string | undefined>;
};

const async_nop = async () => {};

const frida_scripts = {
    android: {
        get_prefs: `var app_ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
var pref_mgr = Java.use('android.preference.PreferenceManager').getDefaultSharedPreferences(app_ctx);
var HashMapNode = Java.use('java.util.HashMap$Node');

var prefs = {};

var iterator = pref_mgr.getAll().entrySet().iterator();
while (iterator.hasNext()) {
    var entry = Java.cast(iterator.next(), HashMapNode);
    prefs[entry.getKey().toString()] = entry.getValue().toString();
}

send({ name: "get_obj_from_frida_script", payload: prefs });`,
    },
    ios: {
        get_prefs: `// Taken from: https://codeshare.frida.re/@dki/ios-app-info/
function dictFromNSDictionary(nsDict) {
    var jsDict = {};
    var keys = nsDict.allKeys();
    var count = keys.count();
    for (var i = 0; i < count; i++) {
        var key = keys.objectAtIndex_(i);
        var value = nsDict.objectForKey_(key);
        jsDict[key.toString()] = value.toString();
    }

    return jsDict;
}
var prefs = ObjC.classes.NSUserDefaults.alloc().init().dictionaryRepresentation();
send({ name: "get_obj_from_frida_script", payload: dictFromNSDictionary(prefs) });`,
    },
};

const ipa_info = async (ipa_path: string) => {
    const fd = await fs.open(ipa_path, 'r');
    return (await _ipaInfo(fd)) as { info: Record<string, unknown>; mobileprovision: unknown };
};
const get_obj_from_frida_script = async (pid: number | undefined, script: string) => {
    try {
        if (!pid) throw new Error('Must provide pid.');
        const frida_device = await frida.getUsbDevice();
        const frida_session = await frida_device.attach(pid);
        const frida_script = await frida_session.createScript(script);
        const result_promise = new Promise<Record<string, unknown>>((res, rej) => {
            frida_script.message.connect((message) => {
                if (message.type === 'send' && message.payload?.name === 'get_obj_from_frida_script')
                    res(message.payload?.payload);
                else rej(message);
            });
        });
        await frida_script.load();

        await frida_session.detach();
        return await result_promise; // We want this to be caught here if it fails, thus the `await`.
    } catch (err) {
        console.error("Couldn't get data from Frida script:", err);
    }
};

export const platform_api = (argv: { frida_ps_path: string }): { android: PlatformApi; ios: PlatformApi } => ({
    android: {
        ensure_frida: async () => {
            const frida_check = await execa('frida-ps -U | grep frida-server', { shell: true, reject: false });
            if (frida_check.exitCode === 0) return;

            await execa('adb', ['root']);
            let adb_tries = 0;
            while ((await execa('adb', ['get-state'], { reject: false })).exitCode !== 0) {
                if (adb_tries > 100) throw new Error('Failed to connect via adb.');
                await pause(250);
                adb_tries++;
            }

            await execa('adb shell "nohup /data/local/tmp/frida-server >/dev/null 2>&1 &"', { shell: true });
            let frida_tries = 0;
            while ((await execa('frida-ps -U | grep frida-server', { shell: true, reject: false })).exitCode !== 0) {
                if (frida_tries > 100) throw new Error('Failed to start Frida.');
                await pause(250);
                frida_tries++;
            }
        },

        install_app: (apk_path) => execa('adb', ['install-multiple', '-g', apk_path], { shell: true }),
        uninstall_app: (app_id) => execa('adb', ['shell', 'pm', 'uninstall', '--user', '0', app_id]).catch(() => {}),

        // Adapted after: https://stackoverflow.com/a/28573364
        get_foreground_app_id: async () => {
            const { stdout } = await execa('adb', ['shell', 'dumpsys', 'activity', 'recents']);
            const foreground_line = stdout.split('\n').find((l) => l.includes('Recent #0'));
            const [, app_id] = Array.from(foreground_line?.match(/A=\d+:(.+?) U=/) || []);
            return app_id ? app_id.trim() : undefined;
        },
        get_pid_for_app_id: async (app_id) => {
            const { stdout } = await execa('adb', ['shell', 'pidof', '-s', app_id]);
            return parseInt(stdout, 10);
        },
        async get_prefs(app_id: string) {
            const pid = await this.get_pid_for_app_id(app_id);
            return get_obj_from_frida_script(pid, frida_scripts.android.get_prefs);
        },

        get_app_version: async (apk_path) =>
            // These sometimes fail with `AndroidManifest.xml:42: error: ERROR getting 'android:icon' attribute: attribute value
            // reference does not exist` but still have the correct version in the output.
            (await execa('aapt', ['dump', 'badging', apk_path], { reject: false })).stdout.match(
                /versionName='(.+?)'/
            )?.[1],
    },
    ios: {
        // On iOS, Frida is automatically provided by the Frida app installed through Cydia.
        ensure_frida: async_nop,

        install_app: (ipa_path) => execa('cfgutil', ['install-app', ipa_path]),
        uninstall_app: (app_id) => execa('cfgutil', ['remove-app', app_id]),

        get_foreground_app_id: async () => {
            const device = await frida.getUsbDevice();
            const app = await device.getFrontmostApplication();
            return app?.identifier;
        },
        get_pid_for_app_id: async (app_id: string) => {
            const { stdout: ps_json } = await execa(argv.frida_ps_path, ['--usb', '--applications', '--json']);
            const ps: { pid: number; name: string; identifier: string }[] = JSON.parse(ps_json);
            return ps.find((p) => p.identifier === app_id)?.pid;
        },
        async get_prefs(app_id: string) {
            const pid = await this.get_pid_for_app_id(app_id);
            return get_obj_from_frida_script(pid, frida_scripts.ios.get_prefs);
        },

        get_app_version: async (ipa_path) =>
            (await ipa_info(ipa_path)).info.CFBundleShortVersionString as string | undefined,
    },
});
