import { join } from 'path';
import fs from 'fs-extra';
import mapObject from 'map-obj';
// @ts-ignore
import dirname from 'es-dirname';
import { db, pg } from './common/db.js';
import { obj_sort } from './common/util.js';
import { data_argv } from './common/argv.js';
import {
    platforms,
    dialogQuery,
    getDialogTypeCounts,
    getViolationCounts,
    getTopApps,
    indicators,
    getRequestsForIndicator,
} from './common/query.js';

const argv = data_argv();

const data_dir = join(dirname(), '../data');

const percentage = (a: number, b: number) => `${((a / b) * 100).toFixed(2)} %`;
const expandWithPercentages = (objOrNum: Record<string, number> | number, reference: number) =>
    typeof objOrNum === 'number'
        ? [objOrNum, percentage(objOrNum, reference)]
        : mapObject(objOrNum, (key, value) => [key, [value, percentage(value, reference)]]);

const printDialogAndViolationOverview = async () => {
    for (const platform of ['all', ...platforms]) {
        const platform_condition = platform === 'all' ? '' : `platform = '${platform}'`;
        console.log('=================================================================');
        console.log('Data for platform:', platform);
        console.log('=================================================================');
        console.log();

        const total_count = await dialogQuery(platform_condition);
        console.log('Total apps:', total_count);
        console.log();

        // Prevalence of different dialog types
        const dialog_type_counts = await getDialogTypeCounts(platform_condition);
        console.log('Apps per dialog type:', expandWithPercentages(dialog_type_counts, total_count));
        console.log();

        // Violations
        const dialog_count = dialog_type_counts.all_dialog;

        const violation_counts = await getViolationCounts(platform_condition);
        console.log('Violations (of all apps with dialog):', expandWithPercentages(violation_counts, dialog_count));
        console.log();

        // TCF data
        const only_old_specification_count = await dialogQuery(
            "cast(prefs as text) ~* 'IABConsent' and not cast(prefs as text) ~* 'IABTCF'",
            platform_condition
        );
        console.log(
            'Apps only using mobile TCF 1.0 but not TCF 2.0 (of all apps):',
            expandWithPercentages(only_old_specification_count, total_count)
        );

        console.log();
        console.log();
    }
};

const computeDialogData = async () => {
    const top_apps = getTopApps();

    // Dialog data
    const dialogs = await db.many(
        `select name, platform, version, verdict, violations from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app;`
    );
    const dialogs_csv =
        'name,platform,version,categories,best_position,best_position_set,verdict,stops_after_reject,accept_color_highlight,ambiguous_accept_button,ambiguous_reject_button,accept_larger_than_reject,accept_button_without_reject_button\n' +
        dialogs
            .map((d) => {
                const top_data = top_apps[`${d.platform as 'android' | 'ios'}::${d.name as string}`];
                return `${[
                    d.name,
                    d.platform,
                    d.version,
                    top_data.categories.length === 1 ? top_data.categories[0] : '<multiple>',
                    top_data.best_position,
                    Math.floor(top_data.best_position / 10) * 10,
                    d.verdict,
                    ...[
                        'stops_after_reject',
                        'accept_color_highlight',
                        'ambiguous_accept_button',
                        'ambiguous_reject_button',
                        'accept_larger_than_reject',
                        'accept_button_without_reject_button',
                    ].map((v) => d.violations[v]),
                ].join(',')}`;
            })
            .join('\n');
    await fs.writeFile(join(data_dir, 'dialogs.csv'), dialogs_csv);
};

const computeIndicatorData = async () => {
    // Indicator data
    const indicator_occurrences: Record<string, number> = {};
    const indicator_apps: Record<string, number> = {};
    for (const [name, strings] of Object.entries(indicators)) {
        const requests = await getRequestsForIndicator(strings);
        const app_count = [...new Set(requests.map((r) => r.name))].length;
        if (app_count > 1) {
            indicator_occurrences[name] = requests.length;
            indicator_apps[name] = app_count;
        }
    }
    await fs.writeFile(
        join(data_dir, 'indicator_occurrences.json'),
        JSON.stringify(obj_sort(indicator_occurrences, 'value_desc'), null, 4)
    );
    await fs.writeFile(
        join(data_dir, 'indicator_apps.json'),
        JSON.stringify(obj_sort(indicator_apps, 'value_desc'), null, 4)
    );
};

const computeTcfData = async () => {
    const tcf_rows = await db.many(
        "select a.name, a.platform, dialogs.verdict, dialogs.violations, dialogs.prefs from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app where cast(prefs as text) ~* 'IABTCF_';"
    );

    const keys = (type: 'initial' | 'accepted' | 'rejected') =>
        tcf_rows
            .map((r) => Object.keys(r.prefs[type] || {}))
            .flat()
            .filter((k) => k.startsWith('IABTCF_'))
            .reduce<Record<string, number>>((acc, cur) => ({ ...acc, [cur]: (acc[cur] || 0) + 1 }), {});
    const sorted_keys = (type: 'initial' | 'accepted' | 'rejected') => obj_sort(keys(type), 'value_desc');
    await fs.writeFile(
        join(data_dir, 'tcf_keys.json'),
        JSON.stringify(
            { initial: sorted_keys('initial'), accepted: sorted_keys('accepted'), rejected: sorted_keys('rejected') },
            null,
            4
        )
    );

    const cmp_list = JSON.parse(await fs.readFile(join(data_dir, 'tcf-upstream/cmp-list.json'), 'utf-8'));
    const tcf_cmps = obj_sort(
        (
            await db.many(
                "select prefs->'initial'->'IABTCF_CmpSdkID' cmp_id, count(1) from dialogs where prefs->'initial'->'IABTCF_CmpSdkID' is not null group by cmp_id order by count(1) desc;"
            )
        )
            .map((r) => ({ ...r, cmp_name: cmp_list.cmps[r.cmp_id]?.name }))
            .reduce<Record<string, number>>(
                (acc, cur) => ({
                    ...acc,
                    [cur.cmp_name || '<invalid>']: (acc[cur.cmp_name || '<invalid>'] || 0) + +cur.count,
                }),
                {}
            ),
        'value_desc'
    );
    await fs.writeFile(join(data_dir, 'tcf_cmps.json'), JSON.stringify(tcf_cmps, null, 4));
};

(async () => {
    if (argv.overview || argv.all) await printDialogAndViolationOverview();
    if (argv.dialog_data || argv.all) await computeDialogData();
    if (argv.indicator_data || argv.all) await computeIndicatorData();
    if (argv.tcf_data || argv.all) await computeTcfData();

    pg.end();
})();

process.on('unhandledRejection', (err) => {
    console.error('An unhandled promise rejection occurred:', err);
    pg.end();
    process.exit(1);
});
