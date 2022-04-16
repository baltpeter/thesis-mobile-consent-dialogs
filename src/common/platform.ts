import { join } from 'path';
import fs from 'fs-extra';
import { execa, ExecaChildProcess } from 'execa';
// @ts-ignore
import _ipaInfo from 'ipa-extract-info';
import frida from 'frida';
// @ts-ignore
import dirname from 'es-dirname';
import { RunArgvType } from './argv.js';
import { kill_process, pause } from './util.js';

type PlatformApi = {
    ensure_device: () => Promise<void>;
    reset_device: () => Promise<void>;
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
    get_platform_specific_data: (app_id: string) => Promise<Record<string, unknown> | undefined>;
    set_clipboard: (text: string) => Promise<void>;

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
        set_clipboard: (
            text: string
        ) => `var app_ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
var cm = Java.cast(app_ctx.getSystemService("clipboard"), Java.use("android.content.ClipboardManager"));
cm.setText(Java.use("java.lang.StringBuilder").$new("${text}"));
send({ name: "get_obj_from_frida_script", payload: true });`,
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
        set_clipboard: (text: string) => `ObjC.classes.UIPasteboard.generalPasteboard().setString_("${text}");`,
        get_idfv: `var idfv = ObjC.classes.UIDevice.currentDevice().identifierForVendor().toString();
send({ name: "get_obj_from_frida_script", payload: idfv });`,
        grant_location_permission: (app_id: string) =>
            `ObjC.classes.CLLocationManager.setAuthorizationStatusByType_forBundleIdentifier_(4, "${app_id}");`,
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
        const result_promise = new Promise<any>((res, rej) => {
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
    await that.set_clipboard('LDDsvPqQdT');
    if (on_before_start) await on_before_start();
    console.log('Starting app…');
    await that.start_app(app_id);
};

export type PlatformApiAndroid = PlatformApi & {
    _internal: {
        ensure_frida: () => Promise<void>;

        emu_process?: ExecaChildProcess;
        objection_processes: ExecaChildProcess[];
    };
};
export type PlatformApiIos = PlatformApi & {
    _internal: { get_app_id: (app_path: string) => Promise<string | undefined> };
};

export const platform_api = (argv: RunArgvType): { android: PlatformApiAndroid; ios: PlatformApiIos } => ({
    android: {
        _internal: {
            emu_process: undefined,
            objection_processes: [],

            ensure_frida: async () => {
                const frida_check = await execa(`${argv.frida_ps_path} -U | grep frida-server`, {
                    shell: true,
                    reject: false,
                });
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
                while (
                    (await execa(`${argv.frida_ps_path} -U | grep frida-server`, { shell: true, reject: false }))
                        .exitCode !== 0
                ) {
                    if (frida_tries > 100) throw new Error('Failed to start Frida.');
                    await pause(250);
                    frida_tries++;
                }
            },
        },

        async reset_device() {
            console.log('Resetting emulator…');
            await execa('adb', ['emu', 'avd', 'snapshot', 'load', argv.avd_snapshot_name!]);
            await this._internal.ensure_frida();
        },
        async ensure_device() {
            if (!argv.dev) {
                console.log('Starting emulator…');
                if (this._internal.emu_process) await kill_process(this._internal.emu_process);
                this._internal.emu_process = execa('emulator', [
                    '-avd',
                    argv.avd_name!,
                    '-no-audio',
                    '-no-boot-anim',
                    '-writable-system',
                    '-http-proxy',
                    '127.0.0.1:8080',
                    '-no-snapshot-save',
                    '-phone-number',
                    '4915585834346',
                ]);
                await execa(join(dirname(), '../await_emulator.sh'));
            } else {
                if ((await execa('adb', ['get-state'], { reject: false })).exitCode !== 0)
                    throw new Error('You need to start an emulator for dev mode.');
            }

            await this._internal.ensure_frida();
        },
        clear_stuck_modals: async () => {
            // Press back button.
            await execa('adb', ['shell', 'input', 'keyevent', '4']);
            // Press home button.
            await execa('adb', ['shell', 'input', 'keyevent', '3']);
        },

        install_app: (apk_path) => execa('adb', ['install-multiple', '-g', apk_path], { shell: true }),
        uninstall_app: (app_id) =>
            execa('adb', ['shell', 'pm', 'uninstall', '--user', '0', app_id]).catch((err) => {
                // Don't fail if app wasn't installed.
                if (!err.stdout.includes('not installed for 0')) throw err;
            }),
        // Basic permissions are granted at install time, we only need to grant dangerous permissions, see:
        // https://android.stackexchange.com/a/220297.
        set_app_permissions: async (app_id) => {
            const { stdout: perm_str } = await execa('adb', ['shell', 'pm', 'list', 'permissions', '-g', '-d', '-u']);
            const dangerous_permissions = perm_str
                .split('\n')
                .filter((l) => l.startsWith('  permission:'))
                .map((l) => l.replace('  permission:', ''));

            // We expect this to fail for permissions the app doesn't want.
            for (const permission of dangerous_permissions)
                await execa('adb', ['shell', 'pm', 'grant', app_id, permission]).catch(() => {});
        },
        start_app(app_id) {
            // We deliberately don't await that since Objection doesn't exit after the app is started.
            const process = execa(argv.objection_path, [
                '--gadget',
                app_id,
                'explore',
                '--startup-command',
                'android sslpinning disable',
            ]);
            this._internal.objection_processes.push(process);
            return Promise.resolve();
        },
        async reset_app(app_id, apk_path, on_before_start) {
            // Kill leftover Objection processes.
            for (const proc of this._internal.objection_processes) await kill_process(proc);

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
        get_platform_specific_data: async_nop as () => Promise<any>,
        async set_clipboard(text) {
            const launcher_pid = await this.get_pid_for_app_id('com.google.android.apps.nexuslauncher');
            const res = await get_obj_from_frida_script(launcher_pid, frida_scripts.android.set_clipboard(text));
            if (!res) throw new Error('Setting clipboard failed.');
        },

        get_app_version: async (apk_path) =>
            // These sometimes fail with `AndroidManifest.xml:42: error: ERROR getting 'android:icon' attribute: attribute value
            // reference does not exist` but still have the correct version in the output.
            (await execa('aapt', ['dump', 'badging', apk_path], { reject: false })).stdout.match(
                /versionName='(.+?)'/
            )?.[1],
    },
    ios: {
        _internal: {
            get_app_id: async (ipa_path) => (await ipa_info(ipa_path)).info.CFBundleIdentifier as string | undefined,
        },

        // On iOS, we're running a physical device and Frida doesn't need to be started manually.
        reset_device: async_nop,
        ensure_device: async_nop,
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
                const script = await session.createScript(frida_scripts.ios.grant_location_permission(app_id));
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
        async get_platform_specific_data(app_id) {
            const that = this;
            async function get_idfv() {
                const pid = await that.get_pid_for_app_id(app_id);
                return get_obj_from_frida_script(pid, frida_scripts.ios.get_idfv);
            }

            return { idfv: await get_idfv() };
        },
        async set_clipboard(text) {
            const session = await frida.getUsbDevice().then((f) => f.attach('SpringBoard'));
            const script = await session.createScript(frida_scripts.ios.set_clipboard(text));
            await script.load();
            await session.detach();
        },

        get_app_version: async (ipa_path) =>
            (await ipa_info(ipa_path)).info.CFBundleShortVersionString as string | undefined,
    },
});
