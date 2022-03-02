import fs from 'fs-extra';
import { execa } from 'execa';
// @ts-ignore
import _ipaInfo from 'ipa-extract-info';
import frida from 'frida';
import { ArgvType } from './argv.js';
import { pause } from './util.js';

type PlatformApi = {
    ensure_frida: () => Promise<void>;
    clear_stuck_modals: () => Promise<void>;

    install_app: (app_path: string) => Promise<unknown>;
    uninstall_app: (app_id: string) => Promise<unknown>;
    set_app_permissions: (app_id: string) => Promise<unknown>;
    start_app: (app_id: string) => Promise<unknown>;
    /**
     * Uninstall, install, setup, start.
     */
    reset_app: (app_id: string, app_path: string, on_before_start?: () => Promise<void>) => Promise<unknown>;

    get_foreground_app_id: () => Promise<string | undefined>;
    get_pid_for_app_id: (app_id: string) => Promise<number | undefined>;
    get_prefs: (app_id: string) => Promise<Record<string, unknown> | undefined>;

    get_app_version: (app_path: string) => Promise<string | undefined>;
};

const async_nop = async () => {};
const async_unimplemented = (action: string) => async () => {
    throw new Error('Unimplemented on this platform: ' + action);
};

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
const reset_app = async (
    that: PlatformApi,
    app_id: string,
    app_path: string,
    on_before_start?: () => Promise<void>
) => {
    console.log('Resetting and installing app…');
    await that.uninstall_app(app_id); // Won't fail if the app isn't installed anyway.
    await that.install_app(app_path);
    await that.set_app_permissions(app_id);
    await that.clear_stuck_modals();
    if (on_before_start) await on_before_start();
    console.log('Starting app…');
    await that.start_app(app_id);
};

export const platform_api = (argv: ArgvType): { android: PlatformApi; ios: PlatformApi } => ({
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
        clear_stuck_modals: async_unimplemented('clear_stuck_modals'),

        install_app: (apk_path) => execa('adb', ['install-multiple', '-g', apk_path], { shell: true }),
        // TODO: Only fail if app wasn't installed.
        uninstall_app: (app_id) => execa('adb', ['shell', 'pm', 'uninstall', '--user', '0', app_id]).catch(() => {}),
        // Basic permissions are granted at install time. TODO: Grant dangerous permissions.
        set_app_permissions: async_unimplemented('set_app_permissions'),
        start_app: async_unimplemented('start_app'),
        async reset_app(app_id, apk_path, on_before_start) {
            await reset_app(this, app_id, apk_path, on_before_start);
        },

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
        async get_prefs(app_id) {
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
        clear_stuck_modals: async () => {
            await execa('sshpass', [
                '-p',
                argv.idevice_root_pw,
                'ssh',
                `root@${argv.idevice_ip}`,
                `activator send libactivator.system.clear-switcher; activator send libactivator.system.homebutton`,
            ]);
        },

        // We're using `libimobiledevice` instead of `cfgutil` because the latter doesn't wait for the app to be fully
        // installed before exiting.
        install_app: (ipa_path) => execa('ideviceinstaller', ['--install', ipa_path]),
        uninstall_app: (app_id) => execa('ideviceinstaller', ['--uninstall', app_id]),
        set_app_permissions: async (app_id: string) => {
            // prettier-ignore
            const permissions_to_grant = ['kTCCServiceLiverpool', 'kTCCServiceUbiquity', 'kTCCServiceCalendar', 'kTCCServiceAddressBook', 'kTCCServiceReminders', 'kTCCServicePhotos', 'kTCCServiceMediaLibrary', 'kTCCServiceBluetoothAlways', 'kTCCServiceMotion', 'kTCCServiceWillow', 'kTCCServiceExposureNotification'];
            const permissions_to_deny = ['kTCCServiceCamera', 'kTCCServiceMicrophone', 'kTCCServiceUserTracking'];

            // value === 0 for not granted, value === 2 for granted
            const setPermission = async (permission: string, value: 0 | 2) => {
                const timestamp = Math.floor(Date.now() / 1000);
                await execa('sshpass', [
                    '-p',
                    argv.idevice_root_pw,
                    'ssh',
                    `root@${argv.idevice_ip}`,
                    'sqlite3',
                    '/private/var/mobile/Library/TCC/TCC.db',
                    `'INSERT OR REPLACE INTO access VALUES("${permission}", "${app_id}", 0, ${value}, 2, 1, NULL, NULL, 0, "UNUSED", NULL, 0, ${timestamp});'`,
                ]);
            };
            const grantLocationPermission = async () => {
                await execa('sshpass', [
                    '-p',
                    argv.idevice_root_pw,
                    'ssh',
                    `root@${argv.idevice_ip}`,
                    'open com.apple.Preferences',
                ]);
                const session = await frida.getUsbDevice().then((f) => f.attach('Settings'));
                const script = await session.createScript(
                    `ObjC.classes.CLLocationManager.setAuthorizationStatusByType_forBundleIdentifier_(4, "${app_id}");`
                );
                await script.load();
                await session.detach();
            };

            for (const permission of permissions_to_grant) await setPermission(permission, 2);
            for (const permission of permissions_to_deny) await setPermission(permission, 0);
            await grantLocationPermission();
        },
        start_app: (app_id) =>
            execa('sshpass', ['-p', argv.idevice_root_pw, 'ssh', `root@${argv.idevice_ip}`, `open ${app_id}`]),
        async reset_app(app_id, ipa_path, on_before_start) {
            await reset_app(this, app_id, ipa_path, on_before_start);
        },

        get_foreground_app_id: async () => {
            const device = await frida.getUsbDevice();
            const app = await device.getFrontmostApplication();
            return app?.identifier;
        },
        get_pid_for_app_id: async (app_id) => {
            const { stdout: ps_json } = await execa(argv.frida_ps_path, ['--usb', '--applications', '--json']);
            const ps: { pid: number; name: string; identifier: string }[] = JSON.parse(ps_json);
            return ps.find((p) => p.identifier === app_id)?.pid;
        },
        async get_prefs(app_id) {
            const pid = await this.get_pid_for_app_id(app_id);
            return get_obj_from_frida_script(pid, frida_scripts.ios.get_prefs);
        },

        get_app_version: async (ipa_path) =>
            (await ipa_info(ipa_path)).info.CFBundleShortVersionString as string | undefined,
    },
});
