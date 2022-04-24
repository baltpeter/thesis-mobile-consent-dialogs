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
    requestHasIndicator,
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

    const apps = {
        all: await db.many('select * from apps;'),
        accepted: await db.many("select a.* from runs join apps a on a.id = runs.app where run_type='accepted';"),
        rejected: await db.many("select a.* from runs join apps a on a.id = runs.app where run_type='rejected';"),
    };
    const getRequests = (run_type: Request['run_type'] | 'all') =>
        db.manyOrNone<Request>(
            `select * from filtered_requests${run_type === 'all' ? '' : ` where run_type='${run_type}'`};`
        );

    const requests = {
        all: await getRequests('all'),
        initial: await getRequests('initial'),
        accepted: await getRequests('accepted'),
        rejected: await getRequests('rejected'),
    };

    const all_requests_with_adapter = requests.all.filter((r) => adapterForRequest(r));
    console.log(
        `Total requests: ${requests.all.length}, requests with adapter: ${
            all_requests_with_adapter.length
        } (${percentage(all_requests_with_adapter.length, requests.all.length)})`
    );

    const computeAppData = (run_type: keyof typeof requests) => {
        const app_tracker_data: Record<string, Record<string, Set<string>>> = apps[
            run_type === 'initial' ? 'all' : run_type
        ].reduce<Record<string, {}>>((acc, cur) => ({ ...acc, [`${cur.platform}::${cur.name}`]: {} }), {});
        for (const r of requests[run_type]) {
            const app = `${r.platform}::${r.name}`;
            const adapter_data = processRequest(r);

            // One of our adapters was able to process the request.
            if (adapter_data) {
                const data_types = Object.entries(adapter_data)
                    .filter(([key]) => key !== 'tracker')
                    .flatMap(([_, d]) => Object.keys(d));

                const tracker = adapter_data.tracker.name;

                if (!app_tracker_data[app][tracker]) app_tracker_data[app][tracker] = new Set();
                for (const data_type of data_types)
                    app_tracker_data[app][tracker].add(['lat', 'long'].includes(data_type) ? 'location' : data_type);
            }
            // None of our adapters could process the request, so we do indicator matching.
            else {
                for (const [name, strings] of Object.entries({ ...indicators, app_id: [r.name] })) {
                    if (requestHasIndicator(r, strings)) {
                        if (!app_tracker_data[app]['<indicators>']) app_tracker_data[app]['<indicators>'] = new Set();
                        app_tracker_data[app]['<indicators>'].add(name);
                    }
                }
            }
        }

        return app_tracker_data;
    };
    const app_tracker_data = {
        initial: computeAppData('initial'),
        accepted: computeAppData('accepted'),
        rejected: computeAppData('rejected'),
    };

    const hasPseudonymousData = (data_types: Set<string>) =>
        data_types.has('idfa') ||
        data_types.has('idfv') ||
        data_types.has('hashed_idfa') ||
        data_types.has('other_uuids') ||
        data_types.has('public_ip');
    const appTransmitsPseudonymousData = (app: typeof app_tracker_data.initial[string]) =>
        Object.values(app).some((s) => hasPseudonymousData(s));

    for (const run_type of Object.keys(app_tracker_data) as (keyof typeof app_tracker_data)[]) {
        await fs.writeFile(
            join(data_dir, `apps_trackers_data_types_${run_type}.json`),
            JSON.stringify(app_tracker_data[run_type], (_, v) => (v instanceof Set ? [...v].sort() : v), 4)
        );

        const apps_with_id = Object.values(app_tracker_data[run_type]).filter((a) => appTransmitsPseudonymousData(a));
        console.log(
            `For ${run_type} runs: ${apps_with_id.length} of ${
                Object.keys(app_tracker_data[run_type]).length
            } apps (${percentage(
                apps_with_id.length,
                Object.keys(app_tracker_data[run_type]).length
            )}) transmit pseudonymous data.`
        );

        if (run_type !== 'initial') {
            const new_apps = Object.entries(app_tracker_data[run_type]).filter(
                ([app, tracker_data]) =>
                    appTransmitsPseudonymousData(tracker_data) &&
                    !appTransmitsPseudonymousData(app_tracker_data.initial[app])
            );
            console.log(`    -> Of those, ${new_apps.length} apps didn't transmit pseudonymous data initially.`);
        }

        const csv_data = Object.entries(app_tracker_data[run_type]).flatMap(([app, data]) =>
            Object.entries(data).flatMap(([tracker, data_types]) =>
                [...data_types].flatMap((data_type) => ({
                    app_id: app.split('::')[1],
                    tracker,
                    data_type,
                    platform: app.split('::')[0],
                }))
            )
        );
        await fs.writeFile(join(data_dir, `apps_trackers_data_types_${run_type}.csv`), Papa.unparse(csv_data));
    }
};

(async () => {
    if (argv.overview || argv.all) await printDialogAndViolationOverview();
    if (argv.dialog_data || argv.all) await computeDialogData();
    if (argv.tcf_data || argv.all) await computeTcfData();
    if (argv.request_data || argv.all) await computeRequestData();

    pg.end();
})();

process.on('unhandledRejection', (err) => {
    console.error('An unhandled promise rejection occurred:', err);
    pg.end();
    process.exit(1);
});
