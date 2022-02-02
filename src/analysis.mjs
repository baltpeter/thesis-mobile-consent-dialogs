import { join, basename } from 'path';
import glob from 'glob';
import fs from 'fs-extra';

const res_dir = '../data.tmp/labelling';

(async () => {
    const apps = glob
        .sync('*.json', { absolute: true, cwd: res_dir, ignore: ['*_prefs.json'] })
        .map((path) => ({ path, app_id: basename(path, '.json') }))
        .map((a) => ({ ...a, ...JSON.parse(fs.readFileSync(a.path, 'utf-8')) }));

    const percentage = (a, b = undefined) => `(${((a / (b || apps.length)) * 100).toFixed(2)} %)`;

    console.log('Total apps:', apps.length);
    console.log();

    const verdict_count = (verdict) => apps.filter((a) => a.verdict === verdict).length;
    console.log(
        'Apps with dialog:',
        verdict_count('dialog'),
        '+',
        verdict_count('maybe_dialog'),
        percentage(verdict_count('dialog') + verdict_count('maybe_dialog'))
    );
    console.log(
        'Apps with notice:',
        verdict_count('notice'),
        '+',
        verdict_count('maybe_notice'),
        percentage(verdict_count('notice') + verdict_count('maybe_notice'))
    );
    console.log('Apps with link:', verdict_count('link'), percentage(verdict_count('link')));
    console.log(
        '=> Apps with any privacy reference:',
        apps.length - verdict_count('neither'),
        percentage(apps.length - verdict_count('neither'))
    );

    console.log();
    const apps_with_dialog = verdict_count('dialog') + verdict_count('maybe_dialog');
    const violation_count = (violation) => apps.filter((a) => a.violations[violation] === true).length;
    console.log(
        'Dialogs with ambiguous accept button:',
        violation_count('ambiguous_accept_button'),
        percentage(violation_count('ambiguous_accept_button'), apps_with_dialog)
    );
    console.log(
        'Dialogs accept button but no reject button:',
        violation_count('accept_button_without_reject_button'),
        percentage(violation_count('accept_button_without_reject_button'), apps_with_dialog)
    );
    console.log(
        'Dialogs with ambiguous reject button:',
        violation_count('ambiguous_reject_button'),
        percentage(violation_count('ambiguous_reject_button'), apps_with_dialog)
    );
    console.log(
        'Dialogs with accept button larger than reject button:',
        violation_count('accept_larger_than_reject'),
        percentage(violation_count('accept_larger_than_reject'), apps_with_dialog)
    );
    console.log(
        'Dialogs with accept button highlighted through color:',
        violation_count('accept_color_highlight'),
        percentage(violation_count('accept_color_highlight'), apps_with_dialog)
    );
    console.log(
        'Dialogs which stop after reject:',
        violation_count('stops_after_reject'),
        percentage(violation_count('stops_after_reject'), apps_with_dialog)
    );
    const dialogs_with_any_violation = apps.filter((a) => Object.values(a.violations).some((v) => v)).length;
    console.log(
        '=> Dialogs with any violation:',
        dialogs_with_any_violation,
        percentage(dialogs_with_any_violation, apps_with_dialog)
    );

    console.log();
    const prefs = glob
        .sync('*_initial_prefs.json', { absolute: true, cwd: res_dir })
        .map((path) => ({ path, app_id: basename(path, '_initial_prefs.json') }))
        .map((a) => ({
            ...a,
            initial_prefs: JSON.parse(fs.readFileSync(a.path, 'utf-8')),
            ...(fs.existsSync(a.path.replace('_initial', '_accepted'))
                ? { accepted_prefs: JSON.parse(fs.readFileSync(a.path.replace('_initial', '_accepted'), 'utf-8')) }
                : {}),
            ...(fs.existsSync(a.path.replace('_initial', '_rejected'))
                ? { rejected_prefs: JSON.parse(fs.readFileSync(a.path.replace('_initial', '_rejected'), 'utf-8')) }
                : {}),
        }));
    const any_pref_initially = prefs.filter((p) => Object.keys(p.initial_prefs).length > 0);
    console.log(
        'Dialog apps which set any prefs initially:',
        any_pref_initially.length,
        percentage(any_pref_initially.length, apps_with_dialog)
    );
    const tcf_prefs_initially = prefs.filter((p) => Object.keys(p.initial_prefs).some((k) => k.match(/iabtcf/i)));
    const no_tcf_prefs_initially = prefs.filter((p) => !Object.keys(p.initial_prefs).some((k) => k.match(/iabtcf/i)));
    console.log(
        'Dialog apps which set TCF prefs initially:',
        tcf_prefs_initially.length,
        percentage(tcf_prefs_initially.length, apps_with_dialog)
    );
    const tcf_prefs_only_after_accepted = no_tcf_prefs_initially.filter(
        (p) => p.accepted_prefs && Object.keys(p.accepted_prefs).some((k) => k.match(/iabtcf/i))
    );
    console.log(
        'Dialog apps with no initial TCF prefs which set them only after accept:',
        tcf_prefs_only_after_accepted.length,
        percentage(tcf_prefs_only_after_accepted.length, no_tcf_prefs_initially.length)
    );
    const tcf_prefs_only_after_rejected = no_tcf_prefs_initially.filter(
        (p) => p.rejected_prefs && Object.keys(p.rejected_prefs).some((k) => k.match(/iabtcf/i))
    );
    console.log(
        'Dialog apps with no initial TCF prefs which set them only after reject:',
        tcf_prefs_only_after_rejected.length,
        percentage(tcf_prefs_only_after_rejected.length, no_tcf_prefs_initially.length)
    );

    process.exit();
    // ---

    const prefs2 = glob
        .sync(`*`, { absolute: true, cwd: res_dir })
        .map((p) => ({ path: join(p, 'prefs.json'), app_id: basename(p) }))
        .filter((a) => fs.existsSync(a.path))
        .map((a) => ({ ...a, prefs: JSON.parse(fs.readFileSync(a.path, 'utf-8')) }));
    console.log('Apps with readable prefs:', prefs.length);

    const non_empty_prefs = prefs.filter((a) => Object.keys(a.prefs).length > 0);
    console.log('Apps with non-empty prefs:', non_empty_prefs.length);

    const privacy_prefs = non_empty_prefs.filter((a) =>
        Object.keys(a.prefs).some((k) => k.match(/gdpr|iabtcf|didomi|IABUSPrivacy_String/i))
    );
    console.log('Apps with privacy-related prefs:', privacy_prefs.length);
    console.log(privacy_prefs.map((a) => [a.app_id, Object.keys(a.prefs)]));
})();
