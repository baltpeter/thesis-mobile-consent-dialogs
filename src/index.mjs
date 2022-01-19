import { join } from 'path';
import glob from 'glob';
import fs from 'fs-extra';
import { execa } from 'execa';
import { remote as wdRemote } from 'webdriverio';
import chalk from 'chalk';
import { timeout } from 'promise-timeout';
import {
    button_id_fragments,
    dialog_id_fragments,
    button_text_fragments,
    dialog_text_fragments,
    notice_text_fragments,
    link_text_fragments,
    keywords_regular,
    keywords_half,
} from './indicators.mjs';

const REQUIRED_SCORE = 1;

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
            console.log(chalk.bold(`${msg}:`), val.replace(/\n/g, ' '), chalk.underline(`(${r})`));
        }
    }
    return res;
};
const decide = (keyword_score, has_dialog, button_count, has_notice, has_link) => {
    if (keyword_score < REQUIRED_SCORE && !has_link) return 'neither';

    if (has_dialog && button_count >= 1) return 'dialog';
    if (has_notice) return 'notice';
    if (keyword_score + (has_link ? 1 : 0) >= 3) {
        if (button_count >= 1) return 'maybe_dialog';
        return 'maybe_notice';
    }
    if (has_link) return 'link';

    return 'neither';
};

async function main() {
    const app_ids = glob.sync(`*`, { absolute: false, cwd: apps_dir });

    for (const app_id of app_ids) {
        let client;
        try {
            const out_prefix = join(out_dir, app_id);
            if (fs.existsSync(`${out_prefix}.json`)) continue;

            console.log(chalk.bgWhite.black(app_id));

            // Install app.
            await execa('adb', ['install-multiple', '-g', join(apps_dir, app_id, '*.apk')], { shell: true });

            // Start app.
            await execa('adb', ['shell', 'monkey', '-p', app_id, '-v', 1, '--dbg-no-events']);
            await pause(20000);

            // Create Appium session and set geolocation.
            client = await wdRemote({
                path: '/wd/hub',
                port: 4723,
                capabilities: {
                    platformName: 'Android',
                    platformVersion: '11',
                    deviceName: 'ignored-on-android',
                },
                logLevel: 'warn',
            });
            await client.setGeoLocation({ latitude: '52.2734031', longitude: '10.5251192', altitude: '77.23' });

            // Collect indicators.
            let has_dialog = false;
            let button_count = 0;
            let has_notice = false;
            let has_link = false;
            let keyword_score = 0;

            const elements = await timeout(client.findElements('xpath', '//*'), 15000);
            try {
                for (const el of elements) {
                    const id = await timeout(client.getElementAttribute(el.ELEMENT, 'resource-id'), 5000);
                    if (id) {
                        if (testAndLog(button_id_fragments, id, 'has button ID', 4)) button_count++;
                        if (testAndLog(dialog_id_fragments, id, 'has dialog ID')) has_dialog = true;
                    }

                    const text = await timeout(client.getElementText(el.ELEMENT), 5000);
                    if (text) {
                        if (process.argv.includes('--debug-text')) console.log(text);

                        if (testAndLog(button_text_fragments, text, 'has button text', 2)) button_count++;
                        if (testAndLog(dialog_text_fragments, text, 'has dialog text')) has_dialog = true;
                        if (testAndLog(notice_text_fragments, text, 'has notice text')) has_notice = true;
                        if (testAndLog(link_text_fragments, text, 'has privacy policy link')) has_link = true;

                        const regular_keywords = testAndLog(keywords_regular, text, 'has 1p keyword', false, true);
                        const half_keywords = testAndLog(keywords_half, text, 'has 1/2p keyword', false, true);
                        keyword_score += regular_keywords.length + half_keywords.length / 2;
                    }
                }
            } catch (err) {
                console.error(err);
            }

            // Take screenshot and save result.
            const verdict = decide(keyword_score, has_dialog, button_count, has_notice, has_link);

            await client.saveScreenshot(`${out_prefix}.png`);
            fs.writeFileSync(
                `${out_prefix}.json`,
                JSON.stringify({ verdict, keyword_score, has_dialog, button_count, has_notice, has_link }, null, 4)
            );

            console.log(
                `has_dialog=${has_dialog}, button_count=${button_count}, has_notice=${has_notice}, has_link=${has_link}, keyword_score=${keyword_score}`
            );
            console.log(chalk.redBright('Verdict:'), verdict);

            if (process.argv.includes('--debug-tree')) console.log(await client.getPageSource());

            // Clean up.
            await client.deleteSession();
            await execa('adb', ['shell', 'pm', 'uninstall', '--user', 0, app_id]);
            console.log();
        } catch (err) {
            console.error(err);

            if (client) await client.deleteSession();
            await execa('adb', ['shell', 'pm', 'uninstall', '--user', 0, app_id]).catch(() => {});

            console.log();
        }
    }
}

main();
