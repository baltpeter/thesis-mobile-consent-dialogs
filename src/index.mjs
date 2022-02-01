import { join } from 'path';
import glob from 'glob';
import fs from 'fs-extra';
import { execa } from 'execa';
import { remote as wdRemote } from 'webdriverio';
import chalk from 'chalk';
import { timeout } from 'promise-timeout';
import getImageColors from 'get-image-colors';
import chroma from 'chroma-js';
import frida from 'frida';
import {
    // button_id_fragments,
    dialog_id_fragments,
    button_text_fragments,
    dialog_text_fragments,
    link_text_fragments,
    keywords_regular,
    keywords_half,
} from './indicators.mjs';
import { adb_get_foreground_app_id, adb_get_pid_for_app_id } from './util.mjs';

const REQUIRED_SCORE = 1;

const run_for_open_app_only = process.argv.includes('--dev');
let log_indicators = true;

const apps_dir = '/media/benni/storage2/tmp/apks';
const out_dir = join('..', 'data.tmp', 'labelling');
fs.ensureDirSync(out_dir);

const pause = (duration_in_ms) => new Promise((res) => setTimeout(res, duration_in_ms));

const fragmentTest = (frags, val, length_factor = false, multiple_matches = false) =>
    frags[multiple_matches ? 'filter' : 'find'](
        (frag) => frag.test(val) && (length_factor ? val.length < length_factor * frag.source.length : true) && frag
    );
const testAndLog = (frags, val, msg, length_factor = false, multiple_matches = false) => {
    const res = fragmentTest(frags, val, length_factor, multiple_matches);
    if (res) {
        for (const r of Array.isArray(res) ? res : [res]) {
            if (log_indicators) console.log(chalk.bold(`${msg}:`), val.replace(/\n/g, ' '), chalk.underline(`(${r})`));
        }
    }
    return res;
};
const decide = (keyword_score, has_dialog, button_count, has_link) => {
    if (keyword_score < REQUIRED_SCORE && !has_link) return 'neither';

    if (has_dialog) {
        if (button_count >= 1) return 'dialog';
        return 'notice';
    }
    if (keyword_score + (has_link ? 1 : 0) >= 3) {
        if (button_count >= 1) return 'maybe_dialog';
        return 'maybe_notice';
    }
    if (has_link) return 'link';

    return 'neither';
};

const ensure_frida = async () => {
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
};

async function main() {
    const app_ids = run_for_open_app_only
        ? [await adb_get_foreground_app_id()]
        : glob.sync(`*`, { absolute: false, cwd: apps_dir });
    if (run_for_open_app_only && app_ids[0] === undefined) throw new Error('You need to start an app!');

    await ensure_frida();

    for (const app_id of app_ids) {
        let client;
        let out_prefix;
        try {
            out_prefix = join(out_dir, app_id);
            if (!run_for_open_app_only) {
                if (fs.existsSync(`${out_prefix}.json`)) continue;

                console.log(chalk.bgWhite.black(app_id));

                // Install app.
                await execa('adb', ['install-multiple', '-g', join(apps_dir, app_id, '*.apk')], { shell: true });
            }

            // Create Appium session and set geolocation.
            client = await wdRemote({
                path: '/wd/hub',
                port: 4723,
                capabilities: {
                    platformName: 'Android',
                    'appium:automationName': 'UiAutomator2',
                    'appium:platformVersion': '11',
                    'appium:deviceName': 'ignored-on-android',
                    'appium:app': join(apps_dir, app_id, `${app_id}.apk`),
                    'appium:noReset': false,
                    'appium:autoGrantPermissions': true, // TODO
                    // This isn't reliable if we don't know the target activity and we're waiting ourselves anyway.
                    'appium:appWaitForLaunch': false,
                    'appium:appWaitActivity': '*',
                },
                logLevel: 'warn',
            });
            await pause(run_for_open_app_only ? 2000 : 10000); // TODO: Increase to 60s.
            await client.setGeoLocation({ latitude: '52.2734031', longitude: '10.5251192', altitude: '77.23' });
            // For some reason, the first `findElements()` call in a session doesn't find elements inside webviews. As a
            // workaround, we can just do any `findElements()` call with results we don't care about first.
            await timeout(client.findElements('xpath', '/invalid/webview-workaround-hack'), 15000);

            // Collect indicators.
            const collect_indicators = async () => {
                let has_dialog = false;
                const buttons = {
                    clear_affirmative: [],
                    clear_negative: [],
                    hidden_affirmative: [],
                    hidden_negative: [],

                    get all_affirmative() {
                        return [...this.clear_affirmative, ...this.hidden_affirmative];
                    },
                    get all_negative() {
                        return [...this.clear_negative, ...this.hidden_negative];
                    },
                };
                let has_link = false;
                let keyword_score = 0;

                const elements = await timeout(client.findElements('xpath', '//*'), 15000);
                try {
                    for (const el of elements) {
                        const id = await timeout(client.getElementAttribute(el.ELEMENT, 'resource-id'), 5000);
                        if (id) {
                            // if (testAndLog(button_id_fragments, id, 'has button ID', 4)) button_count++;
                            if (testAndLog(dialog_id_fragments, id, 'has dialog ID')) has_dialog = true;
                        }

                        const text = await timeout(client.getElementText(el.ELEMENT), 5000);
                        if (text) {
                            if (process.argv.includes('--debug-text')) console.log(text);

                            if (testAndLog(button_text_fragments.clear_affirmative, text, 'has ca button text', 2))
                                buttons.clear_affirmative.push(el);
                            else if (testAndLog(button_text_fragments.clear_negative, text, 'has cn button text', 2))
                                buttons.clear_negative.push(el);
                            else if (
                                testAndLog(button_text_fragments.hidden_affirmative, text, 'has ha button text', 2)
                            )
                                buttons.hidden_affirmative.push(el);
                            else if (testAndLog(button_text_fragments.hidden_negative, text, 'has hn button text', 2))
                                buttons.hidden_negative.push(el);

                            if (testAndLog(dialog_text_fragments, text, 'has dialog text')) has_dialog = true;
                            if (testAndLog(link_text_fragments, text, 'has privacy policy link')) has_link = true;

                            const regular_keywords = testAndLog(keywords_regular, text, 'has 1p keyword', false, true);
                            const half_keywords = testAndLog(keywords_half, text, 'has 1/2p keyword', false, true);
                            keyword_score += regular_keywords.length + half_keywords.length / 2;
                        }
                    }
                } catch (err) {
                    console.error(err);
                }

                return { has_dialog, buttons, has_link, keyword_score };
            };

            const { has_dialog, buttons, has_link, keyword_score } = await collect_indicators();
            const button_count = Object.values(buttons).reduce((acc, cur) => acc + cur.length, 0);

            const verdict = decide(keyword_score, has_dialog, button_count, has_link);

            console.log(
                `has_dialog=${has_dialog}, button_count=${button_count}, has_link=${has_link}, keyword_score=${keyword_score}`
            );
            console.log(chalk.redBright('Verdict:'), verdict);

            // Detect violations.
            const violations = {
                ambiguous_accept_button: false,
                accept_button_without_reject_button: false,
                ambiguous_reject_button: false,
                accept_larger_than_reject: false,
                accept_color_highlight: false,
                stops_after_reject: false,
            };
            if (['dialog', 'maybe_dialog'].includes(verdict)) {
                // Unambiguous "accept" button (not "okay").
                if (buttons.clear_affirmative.length < 1) violations.ambiguous_accept_button = true;

                // Unambiguous "reject" button if there is an "accept" button.
                if (buttons.clear_affirmative.length + buttons.hidden_affirmative.length > 0) {
                    if (buttons.clear_negative.length + buttons.hidden_negative.length < 1)
                        violations.accept_button_without_reject_button = true;
                    else if (buttons.clear_negative.length < 1) violations.ambiguous_reject_button = true;
                }

                // "Accept" button not highlighted compared to "reject" button.
                // TODO: What if there is more than one of each button type?
                if (buttons.all_affirmative.length === 1 && buttons.all_negative.length === 1) {
                    // Compare button sizes.
                    const affirmative_rect = await timeout(
                        client.getElementRect(buttons.all_affirmative[0].ELEMENT),
                        5000
                    );
                    const negative_rect = await timeout(client.getElementRect(buttons.all_negative[0].ELEMENT), 5000);
                    const affirmative_size = affirmative_rect.width * affirmative_rect.height;
                    const negative_size = negative_rect.width * negative_rect.height;
                    if (affirmative_size / negative_size > 1.5) violations.accept_larger_than_reject = true;
                    console.log('button size factor:', affirmative_size / negative_size);

                    // Compare button colors.
                    const affirmative_screenshot = Buffer.from(
                        await client.takeElementScreenshot(buttons.all_affirmative[0].ELEMENT),
                        'base64'
                    );
                    const negative_screenshot = Buffer.from(
                        await client.takeElementScreenshot(buttons.all_negative[0].ELEMENT),
                        'base64'
                    );

                    const affirmative_color = (
                        await getImageColors(affirmative_screenshot, { count: 1, type: 'image/png' })
                    )[0];
                    const negative_color = (
                        await getImageColors(negative_screenshot, { count: 1, type: 'image/png' })
                    )[0];
                    const color_difference = chroma.deltaE(affirmative_color, negative_color);
                    console.log('color difference:', color_difference);
                    if (color_difference > 30) violations.accept_color_highlight = true;
                }

                // Using app needs to be possible after refusing/withdrawing consent.
                if (buttons.all_negative.length === 1) {
                    // Ensure the app is still running in the foreground (4), see: http://appium.io/docs/en/commands/device/app/app-state/
                    if ((await client.queryAppState(app_id)) === 4) {
                        await client.elementClick(buttons.all_negative[0].ELEMENT);
                        await pause(2000);

                        if ((await client.queryAppState(app_id)) !== 4) violations.stops_after_reject = true;
                    }
                }
            }

            console.log();
            console.log(chalk.redBright('Violations:'));
            console.log(violations);

            // Save prefs.
            if (['dialog', 'maybe_dialog'].includes(verdict)) {
                log_indicators = false;

                const get_prefs = async () => {
                    try {
                        const frida_device = await frida.getUsbDevice();
                        const pid = await adb_get_pid_for_app_id(app_id);
                        if (!pid) throw new Error("App to analyze doesn't seem to be running.");

                        const frida_session = await frida_device.attach(pid);
                        const frida_script = await frida_session.createScript(`
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
                        const result_promise = new Promise((res, rej) => {
                            frida_script.message.connect((message) => {
                                if (message.type === 'send' && message.payload?.name === 'app_prefs')
                                    res(message.payload?.payload);
                                else rej(message);
                            });
                        });
                        await frida_script.load();

                        await frida_session.detach();
                        return await result_promise; // We want this to be caught here if it fails, thus the `await`.
                    } catch (err) {
                        console.error("Couldn't get prefs:", err);
                    }
                };

                await client.reset();
                await pause(2000);

                const { buttons: buttons1 } = await collect_indicators();
                const initial_prefs = await get_prefs();

                if (!run_for_open_app_only)
                    fs.writeFileSync(`${out_prefix}_initial_prefs.json`, JSON.stringify(initial_prefs, null, 4));

                if (buttons1.all_affirmative.length === 1) {
                    client.elementClick(buttons1.all_affirmative[0].ELEMENT);
                    await pause(2000);

                    const accepted_prefs = await get_prefs();
                    if (!run_for_open_app_only)
                        fs.writeFileSync(`${out_prefix}_accepted_prefs.json`, JSON.stringify(accepted_prefs, null, 4));
                }

                if (buttons1.all_negative.length === 1) {
                    // We only need to reset if there was an affirmative button that we clicked, otherwise we are in a
                    // reset state anyway.
                    if (buttons1.all_affirmative.length === 1) {
                        await client.reset();
                        await pause(2000);
                    }

                    const { buttons: buttons2 } = await collect_indicators();
                    client.elementClick(buttons2.all_negative[0].ELEMENT);
                    await pause(2000);

                    const rejected_prefs = await get_prefs();
                    if (!run_for_open_app_only)
                        fs.writeFileSync(`${out_prefix}_rejected_prefs.json`, JSON.stringify(rejected_prefs, null, 4));
                }
            }

            // Take screenshot and save result.
            if (!run_for_open_app_only) {
                // Apps with the "secure" flag set cannot be screenshotted. TODO: Can this be circumvented?
                await client
                    .saveScreenshot(`${out_prefix}.png`)
                    .catch(() => console.error("Couldn't save screenshot for", app_id));
                fs.writeFileSync(
                    `${out_prefix}.json`,
                    JSON.stringify(
                        {
                            verdict,
                            keyword_score,
                            has_dialog,
                            button_counts: buttons,
                            button_count,
                            has_link,
                            violations,
                        },
                        null,
                        4
                    )
                );
            }

            if (process.argv.includes('--debug-tree')) console.log(await client.getPageSource());

            // Clean up.
            await client.deleteSession();
            if (!run_for_open_app_only) await execa('adb', ['shell', 'pm', 'uninstall', '--user', 0, app_id]);
            console.log();
        } catch (err) {
            console.error(`Analyzing ${app_id} failed:`, err);

            if (client) await client.deleteSession();
            if (!run_for_open_app_only) {
                await execa('adb', ['shell', 'pm', 'uninstall', '--user', 0, app_id]).catch(() => {});
                fs.removeSync(`${out_prefix}.json`);
            }

            console.log();
        }
    }
}

main();
