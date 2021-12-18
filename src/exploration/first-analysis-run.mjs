import { join } from 'path';
import glob from 'glob';
import fs from 'fs-extra';
import { execa } from 'execa';
import frida from 'frida';

const apps_dir = '/media/benni/storage2/tmp/apks';
const out_dir = '../../data.tmp';

const pause = (duration_in_ms) => new Promise((res) => setTimeout(res, duration_in_ms));

(async () => {
    const app_ids = glob.sync(`*`, { absolute: false, cwd: apps_dir });

    for (const app_id of app_ids) {
        try {
            const dir = join(out_dir, app_id);
            if (fs.existsSync(dir)) continue;
            fs.ensureDirSync(dir);

            console.log(app_id);

            // Install app.
            await execa('adb', ['install-multiple', '-g', join(apps_dir, app_id, '*.apk')], { shell: true });

            // Start app.
            await execa('adb', ['shell', 'monkey', '-p', app_id, '-v', 1, '--dbg-no-events']);
            await pause(5000);

            // Save prefs.
            try {
                const device = await frida.getUsbDevice();
                const app = await device.getFrontmostApplication();
                if (app) {
                    const session = await device.attach(app.pid);
                    const script = await session.createScript(`
var app_ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
var pref_mgr = Java.use('android.preference.PreferenceManager').getDefaultSharedPreferences(app_ctx);
var HashMapNode = Java.use('java.util.HashMap$Node');

var prefs = {};

var iterator = pref_mgr.getAll().entrySet().iterator();
while (iterator.hasNext()) {
    var entry = Java.cast(iterator.next(), HashMapNode);
    prefs[entry.getKey().toString()] = entry.getValue().toString();
}

send({ name: "app_prefs", payload: prefs });`);
                    script.message.connect((message) => {
                        if (message.type === 'send' && message.payload?.name === 'app_prefs') {
                            fs.writeFileSync(
                                join(dir, 'prefs.json'),
                                JSON.stringify(message.payload?.payload, null, 4)
                            );
                            const pref_count = Object.keys(message.payload?.payload).length;
                            if (pref_count) console.log(pref_count);
                        } else console.error('Unexpected message:', message);
                    });
                    await script.load();
                    await session.detach();
                }
            } catch (err) {
                console.log('Could not get prefs:', err);
            }

            // Take screenshot.
            const screenshot_process = execa('adb', ['exec-out', 'screencap', '-p']);
            screenshot_process.stdout.pipe(fs.createWriteStream(join(dir, 'screenshot.png')));
            await screenshot_process;

            // Uninstall app.
            await execa('adb', ['shell', 'pm', 'uninstall', '-k', '--user', 0, app_id]);
            console.log();
        } catch (err) {
            console.error(err);

            await execa('adb', ['shell', 'pm', 'uninstall', '-k', '--user', 0, app_id]).catch(() => {});

            console.log();
        }
    }
})();
