const fs = require('fs');
const path = require('path');
const wdio = require('webdriverio');
const chalk = require('chalk');

const REQUIRED_SCORE = 1;

const normalizeFragments = (frags, enforce_word_boundaries = false) =>
    frags
        .map((frag) =>
            typeof frag === 'string'
                ? new RegExp(enforce_word_boundaries ? `\\b${frag.toLowerCase()}\\b` : frag.toLowerCase(), 'i')
                : new RegExp(enforce_word_boundaries ? `\\b${frag.source}\\b` : frag, 'i')
        )
        .map((frag) =>
            frag.source.includes('_') ? [frag, new RegExp(frag.source.replace(/_/g, ''), frag.flags)] : frag
        )
        .flat();
const fragmentTest = (frags, val, length_factor = false, multiple_matches = false) =>
    frags[multiple_matches ? 'filter' : 'find'](
        (frag) => frag.test(val) && (length_factor ? val.length < length_factor * frag.source.length : true) && frag
    );

// prettier-ignore
const button_id_fragments = normalizeFragments(['decline', 'reject', 'accept', 'agree', 'continue', 'yes', 'no', /personali(z|s)e/, 'manage', 'more_info'], true);
// prettier-ignore
const dialog_id_fragments = normalizeFragments(['gdpr', 'consent', /cookie_settings/, 'iab', 'opt_in', 'user_choice', 'vendors?_list'], true);

// prettier-ignore
const button_text_fragments = normalizeFragments([
    'ok', 'okay', 'decline', 'reject', 'refuse', 'accept', 'agree', 'next', 'continue', /customi(z|s)e/, 'more choices', 'yes', 'no', 'exit',
    'widersprechen', 'ablehnen', 'verweigern', 'akzeptieren', 'zustimmen', 'annehmen', 'weiter', 'fortfahren', 'einstellungen', 'anpassen', 'ja', 'nein', /schlie(ß|ss)en/, 'beenden'
], true);
// TODO: Continue the list.
const dialog_text_fragments = normalizeFragments([
    /we care about[^.]{0,10} (privacy|data protection)/,
    /can( always| later)? revoke[^.]{0,15} consent ?(at any time|later)?/,
    /(use|utilise|need|have|set|collect|ask)[^.]{0,25} (cookie|consent)/,
    /by (tapp|click|select|choos)ing [^.]{0,75},? (you|I) (agree|accept|consent|acknowledge|confirm)/,
    /(accept|agree|consent) [^.]{3,35} (privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/,
    /(accept|agree|consent) [^.]{3,35} processing [^.]{3,20} data/,
    /(learn|read|more) [^.]{3,30} (privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/,
    /have read( and understood)? [^.]{3,35} (privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/,

    /(Datenschutz|Privatsphäre) (ist uns wichtig|liegt uns am Herzen)/,
    /wir nehmen[^.]{0,10} (Datenschutz|Privatsphäre) ernst/,
    /(kannst|können)[^.]{0,10} Einwilligung jederzeit[^.]{0,20} widerrufen/,
    /(benutz|verwend|nutz|brauch|benötig|hab|setz|sammel|frag)[^.]{0,25} (Cookie|Zustimmung|Einwilligung|Einverständnis)/,
    /(mit|durch|bei|wenn) [^.]{2,30} (tipp|klick|(aus)?wähl)[^.]{2,65} (akzeptier|stimm|nimm|nehm|bestätig)/,
    /(akzeptier|stimm|nimm|nehm) [^.]{3,35} (Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)/,
    /(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information) [^.]{3,35} (akzeptier|stimm|nimm|nehm)/,
    /(akzeptier|stimm|nimm|nehm) [^.]{3,35} ((Verarbeit(ung|en) [^.]{3,20} Daten)|(Daten(-| )?[^.]{0,10}Verarbeit(ung|en)))/,
    /((Verarbeit(ung|en) [^.]{3,20} Daten)|(Daten(-| )?[^.]{0,10}Verarbeit(ung|en))) [^.]{3,35} (akzeptier|stimm|nimm|nehm)/,
    /(Informationen|mehr)( dazu)? [^.]{0,25}in [^.]{0,20} (Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)/,
    /(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information) [^.]{3,35} (gelesen|Kenntnis)/,
]);

// prettier-ignore
const notice_text_fragments = normalizeFragments([
    /(learn|read) [^.]{3,30} (privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/, /acknowledge [^.]{2,40} (privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/, /by (sign|continu|creat|us|tapp|click|select|choos)ing[^.]{0,75},? (you|I) (agree|accept|consent|acknowledge|confirm)/,
    /(Informationen|mehr)( dazu)? [^.]{0,30}in [^.]{0,25} (Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)/, /(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information) (gelesen|Kenntnis)/, /(mit|durch|bei|wenn) [^.]{2,30} (fortf(a|ä)hr|weitermach|anmeld|registrier|erstell|nutz|tipp|klick|(aus)?wähl)[^.]{2,65} (akzeptier|stimm|nimm|nehm|bestätig)/
]);

// prettier-ignore
const link_text_fragments = normalizeFragments([
    /(privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/,
    /(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)(e|en)?/
], true);

// prettier-ignore
const keywords_regular = normalizeFragments([
    /third-party ad(vertising|s)?/, /(read|store) cookies/, /(ad(vertising|s)?|content|experience) personali(s|z)ation/, /personali(s|z)ed?[^.]{0,10} (ad(vertising|s)?|content|experience)/, /(ad(vertising|s)?|content) (measurement|performance)/, 'analytics', 'data processing purposes', 'audience insights', 'personal data', /user (behaviou?r|data)/, 'GDPR', 'data protection regulation', 'insufficient level of data protection', 'mobile identifiers', /(advertising|ad)-?ID/, /(necessary|essential|needed) cookies/, 'data processing', /(pseudo|ano)nymi(s|z)ed/, /(data protection|privacy) (settings|controls|preferences)/, 'legitimate interest', 'crash data', /(collect|transmit) (information|data)/,
    /Drittanbieter-?(Werbung|Anzeige|Werbeanzeige)/, /Cookies ((aus)?lesen|speichern)/, /personalisierte (Werbung|Anzeige|Werbeanzeige|Inhalt|Erfahrung)/, /(Werbungs?|Anzeigen|Werbeanzeigen|Inhalt(s|e)?|Erfahrungs)-?Personalisierung/, /(Werbungs?|Werbe|Anzeigen|Werbeanzeigen|Inhalt(s|e)?|Erfahrungs)-?(Messung|Performance|Leistung|Zahlen)/, 'Analysetools', /(Zwecke? der Verarbeitung|Verarbeitungszweck)/, 'Zielgruppenwissen', 'personenbezogen', /Nutz(er|ungs)(verhalten|daten)/, /DS-?GVO/, /Datenschutz-?Grundverordnung/, /gleiches? Datenschutzniveau/, /mobile (ID|Kennungs?)-?Nummer/, /(notwendige|erforderliche) Cookies/, /Datenverarbeitung|Verarbeitung (Deiner|Ihrer) Daten/, /(pseudonymisiert|anonymisiert)/, 'Datenschutzeinstellungen', /berechtigte(n|s)? Interesse/, /Crash-?(Daten|Bericht|Information)/, /(Daten|Informationen) (sammeln|übertragen|übermitteln)/
]);
// prettier-ignore
const keywords_half = normalizeFragments([
    /(optimal|better) user experience/, 'European Court of Justice', /(without( any)?|effective) (legal|judicial) remedy/, 'geolocation data', 'third countries', 'IP address', 'app activity', 'consent', 'privacy', 'data protection', /\bprocess(ed|ing)?\b/,
    /(bessert?e|optimale) Nutz(er|ungs)erfahrung/, 'EuGH', /Europäische(r|n)? Gerichtshof/, /wirksame(r|n) Rechtsbehelf/, /(Standort|Geo)-?daten/, 'Drittländer', 'IP-Adresse', 'Aktivitätsdaten', 'Einwilligung', 'Datenschutz', 'Privatsphäre', /verarbeit(en|ung)/
]);

// TODO: Throw away all non-alphanumeric characters?

async function main() {
    const client = await wdio.remote({
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
    console.log(chalk.red('Verdict:'), verdict);
    console.log(
        `has_dialog=${has_dialog}, button_count=${button_count}, has_notice=${has_notice}, has_link=${has_link}, keyword_score=${keyword_score}`
    );

    if (process.argv.includes('--debug-tree')) console.log(await client.getPageSource());

    await client.deleteSession();
}

main();
