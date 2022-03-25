import { basename, join } from 'path';
import glob from 'glob';
import yesno from 'yesno';
// @ts-ignore
import dirname from 'es-dirname';
import { execa, ExecaChildProcess } from 'execa';
import { remote as wdRemote } from 'webdriverio';
import type { Capabilities } from '@wdio/types';
import type { ElementReference } from '@wdio/protocols/build/types';
import chalk from 'chalk';
import { timeout } from 'promise-timeout';
import getImageColors from 'get-image-colors';
import chroma from 'chroma-js';
import { argv } from './common/argv.js';
import { db, pg } from './common/db.js';
import { platform_api } from './common/platform.js';
import {
    dialog_id_fragments,
    button_text_fragments,
    dialog_text_fragments,
    link_text_fragments,
    keywords_regular,
    keywords_half,
} from './common/indicators.js';
import { shuffle, pause, await_proc_start } from './common/util.js';

const required_score = 1;
const app_timeout = 60;
const mitmdump_addon_path = join(dirname(), 'mitm-addon.py');

const run_for_open_app_only = argv.dev;
let log_indicators = true;

const fragmentTest = (frags: RegExp[], val: string, length_factor: false | number = false, multiple_matches = false) =>
    frags[multiple_matches ? 'filter' : 'find'](
        (frag) => frag.test(val) && (length_factor ? val.length < length_factor * frag.source.length : true) && frag
    );
const testAndLog = (
    frags: RegExp[],
    val: string,
    msg: string,
    length_factor: false | number = false,
    multiple_matches = false
) => {
    const res = fragmentTest(frags, val, length_factor, multiple_matches);
    if (res) {
        for (const r of Array.isArray(res) ? res : [res]) {
            if (log_indicators) console.log(chalk.bold(`${msg}:`), val.replace(/\n/g, ' '), chalk.underline(`(${r})`));
        }
    }
    return res;
};
const decide = (keyword_score: number, has_dialog: boolean, button_count: number, has_link: boolean) => {
    if (keyword_score < required_score && !has_link) return 'neither';

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

async function main() {
    if (!run_for_open_app_only) {
        const ok = await yesno({ question: 'Have you disabled PiHole?' });
        if (!ok) process.exit(1);
    }

    const api = platform_api(argv)[argv.platform];

    const app_ids = run_for_open_app_only
        ? [(await api.get_foreground_app_id()) || '']
        : glob.sync(`*`, { absolute: false, cwd: argv.apps_dir }).map((p) => basename(p, '.ipa'));
    if (run_for_open_app_only && app_ids[0] === '') throw new Error('You need to start an app!');

    await api.ensure_device();

    for (const app_id of shuffle(app_ids)) {
        const app_path_main =
            argv.platform === 'android'
                ? join(argv.apps_dir, app_id, `${app_id}.apk`)
                : join(argv.apps_dir, `${app_id}.ipa`);
        // To handle split APKs on Android.
        const app_path_all = argv.platform === 'android' ? join(argv.apps_dir, app_id, '*.apk') : app_path_main;
        const version = await api.get_app_version(app_path_main);

        if (!run_for_open_app_only) {
            const done = await db.any(
                'SELECT 1 FROM apps WHERE name = ${app_id} AND version = ${version} AND platform = ${platform};',
                { app_id, version, platform: argv.platform }
            );
            if (done.length > 0) {
                console.log(chalk.underline(`Skipping ${app_id}@${version} (${argv.platform})…`));
                console.log();
                continue;
            }
        }
        console.log(chalk.underline(`Analyzing ${app_id}@${version} (${argv.platform})…`));

        const { id: db_app_id } = await db.one(
            'INSERT INTO apps (name, version, platform) VALUES(${app_id}, ${version}, ${platform}) RETURNING id;',
            { app_id, version, platform: argv.platform }
        );
        const { id: run_id } = await db.one(
            'INSERT INTO runs (start_time, app) VALUES(now(), ${db_app_id}) RETURNING id;',
            { db_app_id }
        );

        const res = {
            verdict: 'neither',
            violations: {
                ambiguous_accept_button: false,
                accept_button_without_reject_button: false,
                ambiguous_reject_button: false,
                accept_larger_than_reject: false,
                accept_color_highlight: false,
                stops_after_reject: false,
            },
            prefs: {
                initial: undefined as Record<string, any> | undefined,
                accepted: undefined as Record<string, any> | undefined,
                rejected: undefined as Record<string, any> | undefined,
            },
            screenshot: undefined as string | undefined,
        };

        let client: WebdriverIO.Browser, mitmdump: ExecaChildProcess<string>;
        // On iOS, a globally started Appium server tends to break after a few runs, so we just start a new one for each
        // app which adds a bit of overhead but solves the problem.
        const appium: ExecaChildProcess<string> = execa('appium');

        const cleanup = async (failed = false) => {
            console.log('Cleaning up mitmproxy and Appium session…');
            for (const proc of [mitmdump, appium]) {
                if (proc) {
                    proc.kill();
                    await proc.catch(() => {});
                }
            }

            if (client) await client.deleteSession().catch(() => {});
            if (!run_for_open_app_only) {
                console.log('Uninstalling app…');
                await api.uninstall_app(app_id);
            }

            if (failed && !run_for_open_app_only) {
                console.log('Deleting from database…');
                await db.none('DELETE FROM apps WHERE id = ${db_app_id};', { db_app_id });
            }
        };
        process.removeAllListeners('SIGINT');
        process.on('SIGINT', async () => {
            await cleanup(true);
            pg.end();
            process.exit();
        });
        try {
            await api.reset_device();

            console.log('Starting Appium session…');
            await timeout(await_proc_start(appium, 'Appium REST http interface listener started'), 15000);

            // Create Appium session and set geolocation.
            const android_capabilities: Capabilities.Capabilities & {
                'appium:autoGrantPermissions': boolean;
                'appium:appWaitForLaunch': boolean;
            } = {
                platformName: 'Android',
                'appium:automationName': 'UiAutomator2',
                'appium:platformVersion': '11',

                'appium:deviceName': 'ignored-on-android',

                'appium:autoGrantPermissions': true,
                // This isn't reliable if we don't know the target activity and we're waiting ourselves anyway.
                'appium:appWaitForLaunch': false,
                'appium:appWaitActivity': '*',
            };
            const ios_capabilities: Capabilities.Capabilities & Capabilities.AppiumXCUITestCapabilities = {
                platformName: 'iOS',
                'appium:automationName': 'XCUITest',
                'appium:platformVersion': '14.8',

                'appium:deviceName': argv.device_name,
                'appium:udid': argv.device_udid,

                'appium:xcodeOrgId': argv.xcode_org_id,
                'appium:xcodeSigningId': argv.xcode_signing_id,
                'appium:updatedWDABundleId': argv.webdriver_agent_bundle_id,
            };
            const capabilities: Capabilities.Capabilities & { 'appium:autoLaunch': boolean } = {
                ...(argv.platform === 'android' ? android_capabilities : ios_capabilities),

                'appium:appPackage': app_id,
                'appium:autoLaunch': false,
                'appium:noReset': true,
                'appium:fullReset': false,
                'appium:newCommandTimeout': 360,
            };
            client = await wdRemote({
                path: '/wd/hub',
                port: 4723,
                capabilities,
                logLevel: 'warn',
            });
            await client.setGeoLocation({ latitude: '52.23528', longitude: '10.56437', altitude: '77.23' });

            await api.reset_app(app_id, app_path_all, async () => {
                console.log('Starting mitmproxy…');
                mitmdump = execa(argv.mitmdump_path, ['-s', mitmdump_addon_path, '--set', `run=${run_id}`]);
                await timeout(await_proc_start(mitmdump, 'Proxy server listening'), 15000);
            });

            console.log(`Waiting for ${run_for_open_app_only ? 10 : app_timeout} seconds…`);
            await pause(run_for_open_app_only ? 10000 : app_timeout * 1000);

            // Ensure app is still running and in foreground after timeout.
            if ((await client.queryAppState(app_id)) !== 4) throw new Error("App isn't in foreground anymore.");

            // For some reason, the first `findElements()` call in a session doesn't find elements inside webviews. As a
            // workaround, we can just do any `findElements()` call with results we don't care about first.
            await timeout(client.findElements('xpath', '/invalid/webview-workaround-hack'), 15000);

            // Collect indicators.
            const collect_indicators = async () => {
                let has_dialog = false;
                const buttons = {
                    clear_affirmative: [] as ElementReference[],
                    clear_negative: [] as ElementReference[],
                    hidden_affirmative: [] as ElementReference[],
                    hidden_negative: [] as ElementReference[],

                    push(
                        category: 'clear_affirmative' | 'clear_negative' | 'hidden_affirmative' | 'hidden_negative',
                        el: ElementReference
                    ) {
                        if (this[category].some((e) => e.ELEMENT === el.ELEMENT)) return;
                        this[category].push(el);
                    },

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
                        // Only consider elements that the user can actually see.
                        if (!client.isElementDisplayed(el.ELEMENT)) continue;

                        const id = await timeout(
                            client.getElementAttribute(
                                el.ELEMENT,
                                argv.platform === 'android' ? 'resource-id' : 'name'
                            ),
                            5000
                        );
                        if (id) {
                            // if (testAndLog(button_id_fragments, id, 'has button ID', 4)) button_count++;
                            if (testAndLog(dialog_id_fragments, id, 'has dialog ID')) has_dialog = true;
                        }

                        const text = await timeout(client.getElementText(el.ELEMENT), 5000);
                        if (text) {
                            if (argv.debug_text) console.log(text);

                            // On iOS, we sometimes get into a state where Appium sees the system UI, which we can
                            // detect through the presence of the "No SIM" indicator.
                            if (argv.platform === 'ios' && text === 'No SIM')
                                throw new Error(
                                    'Found "No SIM" indicator. There is likely a stuck modal that blocks the actual app.'
                                );

                            if (testAndLog(button_text_fragments.clear_affirmative, text, 'has ca button text', 2))
                                buttons.push('clear_affirmative', el);
                            else if (testAndLog(button_text_fragments.clear_negative, text, 'has cn button text', 2))
                                buttons.push('clear_negative', el);
                            else if (
                                testAndLog(button_text_fragments.hidden_affirmative, text, 'has ha button text', 2)
                            )
                                buttons.push('hidden_affirmative', el);
                            else if (testAndLog(button_text_fragments.hidden_negative, text, 'has hn button text', 2))
                                buttons.push('hidden_negative', el);

                            if (testAndLog(dialog_text_fragments, text, 'has dialog text')) has_dialog = true;
                            if (testAndLog(link_text_fragments, text, 'has privacy policy link')) has_link = true;

                            const regular_keywords = testAndLog(keywords_regular, text, 'has 1p keyword', false, true);
                            const half_keywords = testAndLog(keywords_half, text, 'has 1/2p keyword', false, true);
                            keyword_score +=
                                (regular_keywords as RegExp[]).length + (half_keywords as RegExp[]).length / 2;
                        }
                    }
                } catch (err) {
                    console.error(err);
                }

                return { has_dialog, buttons, has_link, keyword_score };
            };

            log_indicators = true;
            const { has_dialog, buttons, has_link, keyword_score } = await collect_indicators();
            const button_count = buttons.all_affirmative.length + buttons.all_negative.length;

            res.verdict = decide(keyword_score, has_dialog, button_count, has_link);
            // Take screenshot.
            if (!run_for_open_app_only) {
                // Apps with the "secure" flag set cannot be screenshotted. TODO: Can this be circumvented?
                res.screenshot = await client
                    .takeScreenshot()
                    .catch(() => (console.error("Couldn't save screenshot for", app_id), undefined));
            }

            console.log(
                `has_dialog=${has_dialog}, button_count=${button_count}, has_link=${has_link}, keyword_score=${keyword_score}`
            );
            console.log(chalk.redBright('Verdict:'), res.verdict);

            // Detect violations.
            if (['dialog', 'maybe_dialog'].includes(res.verdict)) {
                // Unambiguous "accept" button (not "okay").
                if (buttons.clear_affirmative.length < 1 && buttons.hidden_affirmative.length > 0)
                    res.violations.ambiguous_accept_button = true;

                // Unambiguous "reject" button if there is an "accept" button.
                if (buttons.clear_affirmative.length + buttons.hidden_affirmative.length > 0) {
                    if (buttons.clear_negative.length + buttons.hidden_negative.length < 1)
                        res.violations.accept_button_without_reject_button = true;
                    else if (buttons.clear_negative.length < 1) res.violations.ambiguous_reject_button = true;
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
                    if (affirmative_size / negative_size > 1.5) res.violations.accept_larger_than_reject = true;
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
                    if (color_difference > 30) res.violations.accept_color_highlight = true;
                }

                // Using app needs to be possible after refusing/withdrawing consent.
                if (buttons.all_negative.length === 1) {
                    // Ensure the app is still running in the foreground (4), see: http://appium.io/docs/en/commands/device/app/app-state/
                    if ((await client.queryAppState(app_id)) === 4) {
                        await client.elementClick(buttons.all_negative[0].ELEMENT);
                        await pause(2000);

                        if ((await client.queryAppState(app_id)) !== 4) res.violations.stops_after_reject = true;
                    }
                }
            }

            console.log();
            console.log(chalk.redBright('Violations:'));
            console.log(res.violations);

            // Save prefs.
            if (['dialog', 'maybe_dialog'].includes(res.verdict)) {
                log_indicators = false;

                await api.reset_app(app_id, app_path_all);
                await client.reloadSession();

                await pause(10000);

                const { buttons: buttons1 } = await collect_indicators();
                res.prefs.initial = await api.get_prefs(app_id);

                if (buttons1.all_affirmative.length === 1) {
                    console.log(
                        `Accepting dialog and waiting for ${run_for_open_app_only ? 10 : app_timeout} seconds…`
                    );
                    await client.elementClick(buttons1.all_affirmative[0].ELEMENT);
                    await pause(app_timeout * 1000);

                    res.prefs.accepted = await api.get_prefs(app_id);
                }

                if (buttons1.all_negative.length === 1) {
                    // We only need to reset if there was an affirmative button that we clicked, otherwise we are in a
                    // reset state anyway.
                    if (buttons1.all_affirmative.length === 1) {
                        await api.reset_app(app_id, app_path_all);
                        await client.reloadSession();
                        await pause(10000);
                    }

                    const { buttons: buttons2 } = await collect_indicators();
                    console.log(
                        `Rejecting dialog and waiting for ${run_for_open_app_only ? 10 : app_timeout} seconds…`
                    );
                    await client.elementClick(buttons2.all_negative[0].ELEMENT);
                    await pause(app_timeout * 1000);

                    res.prefs.rejected = await api.get_prefs(app_id);
                }
            }

            // Save result.
            if (!run_for_open_app_only) {
                await db.none(
                    'INSERT INTO dialogs (run,verdict,violations,prefs,screenshot,meta) VALUES (${run_id},${verdict},${violations},${prefs},${screenshot},${meta})',
                    {
                        run_id,
                        verdict: res.verdict,
                        violations: JSON.stringify(res.violations),
                        prefs: JSON.stringify(res.prefs),
                        screenshot: res.screenshot && Buffer.from(res.screenshot, 'base64'),
                        meta: JSON.stringify({ has_dialog, buttons, has_link, keyword_score, button_count }),
                    }
                );
            } else console.log(res);

            if (argv.debug_tree) console.log(await client.getPageSource());

            // Clean up.
            await cleanup();
            console.log();
        } catch (err) {
            console.error(`Analyzing ${app_id} failed:`, err);

            await cleanup(true);

            console.log();
        }
    }

    pg.end();
}

process.on('unhandledRejection', (err) => {
    console.error('An unhandled promise rejection occurred:', err);
    pg.end();
    process.exit(1);
});

main();
