import { basename, join } from 'path';
import fs from 'fs-extra';
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
import { serializeError } from 'serialize-error';
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
import { shuffle, pause, await_proc_start, kill_process } from './common/util.js';

const required_score = 1;
const app_timeout = 60;
const max_button_size_factor = 1.5;
const max_button_color_difference = 30;
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

    const app_ids =
        argv.app_ids ||
        (run_for_open_app_only
            ? [(await api.get_foreground_app_id()) || '']
            : glob.sync(`*`, { absolute: false, cwd: argv.apps_dir }).map((p) => basename(p, '.ipa')));
    if (run_for_open_app_only && app_ids[0] === '') throw new Error('You need to start an app!');

    await api.ensure_device();

    for (const app_id of shuffle(app_ids)) {
        // This isn't exactly clean but I don't know how else to convince TS that `mitmdump` will be assigned a value
        // below.
        let client: WebdriverIO.Browser,
            appium: ExecaChildProcess<string>,
            mitmdump: ExecaChildProcess<string> = undefined as any,
            db_app_id: number;

        const cleanup = async (failed = false) => {
            console.log('Cleaning up mitmproxy and Appium session…');
            for (const proc of [mitmdump, appium]) await kill_process(proc);

            if (client) await client.deleteSession().catch(() => {});
            if (!run_for_open_app_only && argv.platform !== 'android') {
                console.log('Uninstalling app…');
                await api.uninstall_app(app_id);
            }

            if (failed && !run_for_open_app_only && db_app_id) {
                console.log('Deleting from database…');
                await db.none('DELETE FROM apps WHERE id = ${db_app_id};', { db_app_id });
            }
        };

        try {
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

            db_app_id = (
                await db.one(
                    'INSERT INTO apps (name, version, platform) VALUES(${app_id}, ${version}, ${platform}) RETURNING id;',
                    { app_id, version, platform: argv.platform }
                )
            ).id;
            let main_run_id;

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
                platform_specific_data: {} as Record<string, any> | undefined,
                screenshot: undefined as string | undefined,
            };

            // On iOS, a globally started Appium server tends to break after a few runs, so we just start a new one for each
            // app which adds a bit of overhead but solves the problem.
            appium = execa('appium');

            const start_mitmproxy = async (
                run_type: 'initial' | 'rejected' | 'accepted' | 'ignore'
            ): Promise<number | undefined> => {
                if (mitmdump) {
                    console.log('Stopping existing mitmproxy instance…');
                    await kill_process(mitmdump);
                }

                console.log('Starting mitmproxy…');
                if (run_type !== 'ignore') {
                    const { id: run_id } = await db.one(
                        'INSERT INTO runs (start_time, app, run_type) VALUES(now(), ${db_app_id}, ${run_type}) RETURNING id;',
                        { db_app_id, run_type }
                    );
                    mitmdump = execa(argv.mitmdump_path, ['-s', mitmdump_addon_path, '--set', `run=${run_id}`]);
                    await timeout(await_proc_start(mitmdump, 'Proxy server listening'), 15000);
                    return run_id;
                }

                mitmdump = execa(argv.mitmdump_path);
                await timeout(await_proc_start(mitmdump, 'Proxy server listening'), 15000);
            };

            process.removeAllListeners('SIGINT');
            process.on('SIGINT', async () => {
                await cleanup(true);
                pg.end();
                process.exit();
            });

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
                main_run_id = await start_mitmproxy('initial');
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

            res.platform_specific_data = await api.get_platform_specific_data(app_id);

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
                if (buttons.all_affirmative.length > 0 && buttons.all_negative.length > 0) {
                    const element_size_factor = async (el1: string, el2: string) => {
                        const el1_rect = await timeout(client.getElementRect(el1), 5000);
                        const el2_rect = await timeout(client.getElementRect(el2), 5000);

                        const el1_size = el1_rect.width * el1_rect.height;
                        const el2_size = el2_rect.width * el2_rect.height;

                        return el1_size / el2_size;
                    };

                    const element_color_difference = async (el1: string, el2: string) => {
                        const el1_screenshot = Buffer.from(await client.takeElementScreenshot(el1), 'base64');
                        const el2_screenshot = Buffer.from(await client.takeElementScreenshot(el2), 'base64');

                        const el1_color = (await getImageColors(el1_screenshot, { count: 1, type: 'image/png' }))[0];
                        const el2_color = (await getImageColors(el2_screenshot, { count: 1, type: 'image/png' }))[0];

                        return chroma.deltaE(el1_color, el2_color);
                    };

                    // If there is more than one of each button, we can't know which ones to check against each other to
                    // detect whether one is highlighted. Thus, for each affirmative button, we only record a violation
                    // if _every_ negative button is highlighted compared to it.
                    // But it is enough if there is one affirmative button that is highlighted, not all of them need to
                    // be.
                    for (const affirmative_button of buttons.all_affirmative) {
                        // Compare button sizes.
                        if (!res.violations.accept_larger_than_reject) {
                            const violates_size = await buttons.all_negative.reduce(
                                async (acc, cur) =>
                                    (await acc) ||
                                    (await element_size_factor(affirmative_button.ELEMENT, cur.ELEMENT)) >
                                        max_button_size_factor,
                                Promise.resolve(false)
                            );
                            if (violates_size) res.violations.accept_larger_than_reject = true;
                        }

                        // Compare button colors.
                        if (!res.violations.accept_color_highlight) {
                            const violates_color = await buttons.all_negative.reduce(
                                async (acc, cur) =>
                                    (await acc) ||
                                    (await element_color_difference(affirmative_button.ELEMENT, cur.ELEMENT)) >
                                        max_button_color_difference,
                                Promise.resolve(false)
                            );
                            if (violates_color) res.violations.accept_color_highlight = true;
                        }
                    }
                }

                // Using app needs to be possible after refusing/withdrawing consent.
                if (buttons.clear_negative.length > 0 || buttons.hidden_negative.length === 1) {
                    // Ensure the app is still running in the foreground (4), see: http://appium.io/docs/en/commands/device/app/app-state/
                    if ((await client.queryAppState(app_id)) === 4) {
                        await client.elementClick((buttons.clear_negative[0] || buttons.hidden_negative[0]).ELEMENT);
                        await pause(5000);

                        if ((await client.queryAppState(app_id)) !== 4) res.violations.stops_after_reject = true;
                    } else throw new Error('App lost focus while testing for violations.');
                }
            }

            console.log();
            console.log(chalk.redBright('Violations:'));
            console.log(res.violations);

            // Collect traffic after accepting/rejecting dialog; and save corresponding prefs.
            if (['dialog', 'maybe_dialog'].includes(res.verdict)) {
                log_indicators = false;

                await start_mitmproxy('ignore');
                await api.reset_app(app_id, app_path_all);
                await client.reloadSession();

                await pause(10000);

                const { buttons: buttons1 } = await collect_indicators();
                res.prefs.initial = await api.get_prefs(app_id);

                if (buttons1.all_affirmative.length > 0) {
                    console.log(
                        `Accepting dialog and waiting for ${run_for_open_app_only ? 10 : app_timeout} seconds…`
                    );
                    await start_mitmproxy('accepted');
                    await client.elementClick(
                        buttons1.clear_affirmative.length > 0
                            ? buttons1.clear_affirmative[0].ELEMENT
                            : buttons1.all_affirmative[0].ELEMENT
                    );
                    await pause(app_timeout * 1000);

                    res.prefs.accepted = await api.get_prefs(app_id);
                }

                if (buttons1.clear_negative.length > 0) {
                    // We only need to reset if there was an affirmative button that we clicked, otherwise we are in a
                    // reset state anyway.
                    if (buttons1.all_affirmative.length === 1) {
                        await start_mitmproxy('ignore');
                        await api.reset_app(app_id, app_path_all);
                        await client.reloadSession();
                        await pause(10000);
                    }

                    const { buttons: buttons2 } = await collect_indicators();
                    console.log(
                        `Rejecting dialog and waiting for ${run_for_open_app_only ? 10 : app_timeout} seconds…`
                    );
                    await start_mitmproxy('rejected');
                    await client.elementClick(buttons2.clear_negative[0].ELEMENT);
                    await pause(app_timeout * 1000);

                    res.prefs.rejected = await api.get_prefs(app_id);
                }
            }

            // Save result.
            if (!run_for_open_app_only) {
                await db.none(
                    'INSERT INTO dialogs (run,verdict,violations,prefs,screenshot,meta,platform_specific_data) VALUES (${run_id},${verdict},${violations},${prefs},${screenshot},${meta},${platform_specific_data})',
                    {
                        run_id: main_run_id,
                        verdict: res.verdict,
                        violations: JSON.stringify(res.violations),
                        prefs: JSON.stringify(res.prefs),
                        screenshot: res.screenshot && Buffer.from(res.screenshot, 'base64'),
                        meta: JSON.stringify({ has_dialog, buttons, has_link, keyword_score, button_count }),
                        platform_specific_data: JSON.stringify(res.platform_specific_data),
                    }
                );
            } else console.log(res);

            if (argv.debug_tree) console.log(await client.getPageSource());

            // Clean up.
            await cleanup();
            console.log();
        } catch (err) {
            console.error(`Analyzing ${app_id} failed:`, err);

            const err_dir = join(dirname(), '../data/failed-apps.tmp');
            const date = new Date().toISOString();
            await fs.ensureDir(err_dir);
            await fs.writeFile(
                join(err_dir, `${date}-${app_id}.json`),
                JSON.stringify({ app_id, date, error: serializeError(err) }, null, 4)
            );

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
