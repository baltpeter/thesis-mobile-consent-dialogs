import { join } from 'path';
import fs from 'fs-extra';
import { TCString } from '@iabtcf/core';
import Papa from 'papaparse';
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
import { Request, processRequest, adapterForRequest } from './common/extract-request-data.js';

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
    const dialogs = (
        await db.many(
            `select name, platform, version, verdict, violations from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app;`
        )
    ).map((d) => {
        const top_data = top_apps[`${d.platform as 'android' | 'ios'}::${d.name as string}`];
        return {
            name: d.name,
            platform: d.platform,
            version: d.version,
            categories: top_data.categories.length === 1 ? top_data.categories[0] : '<multiple>',
            best_position: top_data.best_position,
            best_position_set: Math.floor(top_data.best_position / 10) * 10,
            verdict: d.verdict,
            stops_after_reject: d.violations.stops_after_reject,
            accept_color_highlight: d.violations.accept_color_highlight,
            ambiguous_accept_button: d.violations.ambiguous_accept_button,
            ambiguous_reject_button: d.violations.ambiguous_reject_button,
            accept_larger_than_reject: d.violations.accept_larger_than_reject,
            accept_button_without_reject_button: d.violations.accept_button_without_reject_button,
        };
    });
    await fs.writeFile(join(data_dir, 'dialogs.csv'), Papa.unparse(dialogs));
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

    const cmp_list = JSON.parse(await fs.readFile(join(data_dir, 'upstream/cmp-list.json'), 'utf-8'));
    const tcf_cmps = obj_sort(
        (
            await db.many(
                "select coalesce(prefs->'initial'->'IABTCF_CmpSdkID', prefs->'accepted'->'IABTCF_CmpSdkID', prefs->'rejected'->'IABTCF_CmpSdkID') cmp_id, count(1) from dialogs where coalesce(prefs->'initial'->'IABTCF_CmpSdkID', prefs->'accepted'->'IABTCF_CmpSdkID', prefs->'rejected'->'IABTCF_CmpSdkID') is not null group by cmp_id order by count(1) desc;"
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

    const get_tc_data = async (type: 'initial' | 'accepted' | 'rejected') =>
        (
            await db.many<{ name: string; platform: 'ios' | 'android'; version: string; tc_string: string }>(
                `select name, platform, version, prefs->'${type}'->'IABTCF_TCString' tc_string from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app where prefs->'${type}'->>'IABTCF_TCString' <> '';`
            )
        )
            .map((a) => ({ ...a, tc_data: TCString.decode(a.tc_string) }))
            .map((a) => ({
                ...a,
                vendorConsents: Array.from(a.tc_data.vendorConsents.values()),
                purposeConsents: Array.from(a.tc_data.purposeConsents.values()),
                publisherConsents: Array.from(a.tc_data.publisherConsents.values()),
                publisherCustomConsents: Array.from(a.tc_data.publisherCustomConsents.values()),
            }));
    const tc_data = { initial: await get_tc_data('initial'), accepted: await get_tc_data('accepted') };
    const tcf_accepted_counts = tc_data.accepted.map((a) => ({
        name: a.name,
        platform: a.platform,
        version: a.version,
        vendorConsents: a.vendorConsents.length,
        purposeConsents: a.purposeConsents.length,
        publisherConsents: a.publisherConsents.length,
        publisherCustomConsents: a.publisherCustomConsents.length,
    }));
    await fs.writeFile(join(data_dir, 'tcf_accepted_counts.csv'), Papa.unparse(tcf_accepted_counts));

    const vendor_list = JSON.parse(await fs.readFile(join(data_dir, 'upstream/vendor-list.json'), 'utf-8'));
    const vendors_empty = Object.values<{ name: string; id: number }>(vendor_list.vendors).map((v) => ({
        name: v.name,
        id: v.id,
        count: 0,
    }));
    const tcf_vendors = tc_data.accepted
        .reduce<typeof vendors_empty>((acc, cur) => {
            for (const vendor_id of cur.vendorConsents) {
                acc.find((v) => v.id === vendor_id)!.count++;
            }
            return acc;
        }, vendors_empty)
        .sort((a, b) => b.count - a.count);

    await fs.writeFile(join(data_dir, 'tcf_vendors.csv'), Papa.unparse(tcf_vendors));

    console.log(tc_data.initial.length);

    const tcf_languages = obj_sort(
        tc_data.initial.reduce<Record<string, number>>(
            (acc, cur) => ({
                ...acc,
                [cur.tc_data.consentLanguage]: (acc[cur.tc_data.consentLanguage] || 0) + 1,
            }),
            {}
        ),
        'value_desc'
    );
    await fs.writeFile(join(data_dir, 'tcf_languages.json'), JSON.stringify(tcf_languages, null, 4));

    // const tcf_gvl_version = obj_sort(
    //     tc_data.initial.reduce<Record<string, number>>(
    //         (acc, cur) => ({
    //             ...acc,
    //             [cur.tc_data.vendorListVersion]: (acc[cur.tc_data.vendorListVersion] || 0) + 1,
    //         }),
    //         {}
    //     ),
    //     'value_desc'
    // );
};

const computeRequestData = async () => {
    const getRequests = (run_type: Request['run_type'] | 'all') =>
        db.manyOrNone<Request>(
            `select * from filtered_requests${run_type === 'all' ? '' : ` where run_type='${run_type}'`};`
        );

    // const requests = {
    //     all: await getRequests('all'),
    //     initial: await getRequests('initial'),
    //     accepted: await getRequests('accepted'),
    //     rejected: await getRequests('rejected'),
    // };

    // const all_requests_with_adapter = requests.all.filter((r) => adapterForRequest(r));
    // console.log(
    //     `Total requests: ${requests.all.length}, requests with adapter: ${
    //         all_requests_with_adapter.length
    //     } (${percentage(all_requests_with_adapter.length, requests.all.length)})`
    // );

    const computeAppData = (requests: Request[]) => {
        const apps: Record<string, Record<string, Set<string>>> = {};
        for (const r of requests) {
            const app = `${r.platform}::${r.name}`;
            const data = processRequest(r);
            if (data) {
                const data_types = Object.entries(data)
                    .filter(([key]) => key !== 'tracker')
                    .flatMap(([_, d]) => Object.keys(d));

                const tracker = data.tracker.name;

                if (!apps[app]) apps[app] = {};
                if (!apps[app][tracker]) apps[app][tracker] = new Set();
                for (const data_type of data_types) apps[app][tracker].add(data_type);
            } else apps[app] = {};
        }
        return apps;
    };
    const isPseudonymous = (data_types: Set<string>) =>
        data_types.has('idfa') ||
        data_types.has('idfv') ||
        data_types.has('hashed_idfa') ||
        data_types.has('other_uuids') ||
        data_types.has('public_ip');

    // for (const run_type of ['initial', 'accepted', 'rejected'] as const) {
    //     const apps = computeAppData(requests[run_type]);
    //     await fs.writeFile(
    //         join(data_dir, `apps_trackers_data_types_${run_type}.json`),
    //         JSON.stringify(apps, (_, v) => (v instanceof Set ? [...v].sort() : v), 4)
    //     );

    //     const apps_with_id = Object.values(apps).filter((a) => Object.values(a).some((s) => isPseudonymous(s)));
    //     console.log(
    //         `For ${run_type} runs: ${apps_with_id.length} of ${Object.keys(apps).length} apps (${percentage(
    //             apps_with_id.length,
    //             Object.keys(apps).length
    //         )}) transmit pseudonymous data.`
    //     );
    // }

    // Requests/hosts per app
    const traffic_counts = await db.many(
        "select name, version, platform, count(1) request_count, count(distinct(host)) host_count from filtered_requests where run_type='initial' group by name, version, platform order by request_count desc, name;"
    );
    await fs.writeFile(join(data_dir, 'app_traffic.csv'), Papa.unparse(traffic_counts));

    // Exodus companies
    const exodus: { name: string; is_in_exodus: boolean; network_signature: string; category: string[] }[] = JSON.parse(
        await fs.readFile(join(data_dir, 'upstream/exodus-trackers.json'), 'utf-8')
    ).trackers;
    const exodus_trackers = exodus.filter((r) => r.is_in_exodus && r.network_signature !== '');

    const tracker_counts: Record<string, number> = {};
    await Promise.all(
        exodus_trackers.map(async ({ name, network_signature }) => {
            const res = await db.one(
                "select count(distinct name) as count from filtered_requests where host ~ ${regex} and run_type='initial';",
                { regex: `${network_signature}$` }
            );

            tracker_counts[name.replace(/ \(.+\)/, '')] = +res.count;
        })
    );
    await fs.writeFile(
        join(data_dir, 'exodus_tracker_counts.json'),
        JSON.stringify(obj_sort(tracker_counts, 'value_desc'), null, 4)
    );
};

(async () => {
    if (argv.overview || argv.all) await printDialogAndViolationOverview();
    if (argv.dialog_data || argv.all) await computeDialogData();
    if (argv.indicator_data || argv.all) await computeIndicatorData();
    if (argv.tcf_data || argv.all) await computeTcfData();
    if (argv.request_data || argv.all) await computeRequestData();

    pg.end();
})();

process.on('unhandledRejection', (err) => {
    console.error('An unhandled promise rejection occurred:', err);
    pg.end();
    process.exit(1);
});
