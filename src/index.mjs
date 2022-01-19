import fs from 'fs';
import path from 'path';
import { remote as wdRemote } from 'webdriverio';
import chalk from 'chalk';
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

const fragmentTest = (frags, val, length_factor = false, multiple_matches = false) =>
    frags[multiple_matches ? 'filter' : 'find'](
        (frag) => frag.test(val) && (length_factor ? val.length < length_factor * frag.source.length : true) && frag
    );

async function main() {
    const client = await wdRemote({
        path: '/wd/hub',
        port: 4723,
        capabilities: {
            platformName: 'Android',
            platformVersion: '11',
            deviceName: 'appium-ma',
            // app: '/path',
            // appPackage: 'com.bonial.kaufda',
            // noReset: false,
        },
        logLevel: 'warn',
    });
    await client.setGeoLocation({ latitude: '52.2734031', longitude: '10.5251192', altitude: '77.23' });

    const check = (frags, val, msg, length_factor = false, multiple_matches = false) => {
        const res = fragmentTest(frags, val, length_factor, multiple_matches);
        if (res) {
            for (const r of Array.isArray(res) ? res : [res]) {
                console.log(chalk.bold(`${msg}:`), val.replace(/\n/g, ' '), chalk.underline(`(${r})`));
            }
        }
        return res;
    };

    let has_dialog = false;
    let button_count = 0;
    let has_notice = false;
    let has_link = false;
    let keyword_score = 0;

    const els = await client.findElements('xpath', '//*');
    // TODO: Seems like this can hang? Timeout?
    try {
        for (const el of els) {
            const id = await client.getElementAttribute(el.ELEMENT, 'resource-id');
            if (id) {
                if (check(button_id_fragments, id, 'has button ID', 4)) button_count++;
                if (check(dialog_id_fragments, id, 'has dialog ID')) has_dialog = true;
            }

            const text = await client.getElementText(el.ELEMENT);
            if (text) {
                if (process.argv.includes('--debug-text')) console.log(text);

                if (check(button_text_fragments, text, 'has button text', 2)) button_count++;
                if (check(dialog_text_fragments, text, 'has dialog text')) has_dialog = true;
                if (check(notice_text_fragments, text, 'has notice text')) has_notice = true;
                if (check(link_text_fragments, text, 'has privacy policy link')) has_link = true;

                const regular_keywords = check(keywords_regular, text, 'has 1p keyword', false, true);
                const half_keywords = check(keywords_half, text, 'has 1/2p keyword', false, true);
                keyword_score += regular_keywords.length + half_keywords.length / 2;
            }
        }
    } catch {}

    const decide = () => {
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
    const verdict = decide();

    console.log();
    console.log(chalk.redBright('Verdict:'), verdict);
    console.log(
        `has_dialog=${has_dialog}, button_count=${button_count}, has_notice=${has_notice}, has_link=${has_link}, keyword_score=${keyword_score}`
    );

    if (process.argv.includes('--debug-tree')) console.log(await client.getPageSource());

    await client.deleteSession();
}

main();
