import { join } from 'path';
import fs from 'fs-extra';
import { TCString } from '@iabtcf/core';
import Papa from 'papaparse';
import mapObject from 'map-obj';
import { match } from 'ts-pattern';
import glob from 'glob';
// @ts-ignore
import dirname from 'es-dirname';
import { z } from 'zod';
import { db, pg } from './common/db.js';
import { obj_sort, jsonify_obj_with_sets } from './common/util.js';
import { data_argv } from './common/argv.js';
import {
    platforms,
    dialogQuery,
    getDialogTypeCounts,
    getViolationCounts,
    getTopApps,
    indicators,
    requestHasIndicator,
    hasPseudonymousData,
    privacy_types_schema,
    privacy_label_data_type_mapping,
    getFilterList,
    cookie_regexes,
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
                if (acc.find((v) => v.id === vendor_id)) acc.find((v) => v.id === vendor_id)!.count++;
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
    const exodus_trackers = exodus
        .filter((r) => r.is_in_exodus && r.network_signature !== '')
        .map((t) => ({ ...t, network_regex: new RegExp(`${t.network_signature}$`, 'i') }));

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
        initial: await db.many("select a.* from runs join apps a on a.id = runs.app where run_type='initial';"),
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

    // Prevalence of Exodus-identified trackers in traffic
    const getTrackerRequests = (reqs: Request[]) =>
        reqs.filter((r) => exodus_trackers.some((t) => t.network_regex.test(r.host)));
    const tracker_requests = {
        all: getTrackerRequests(requests.all),
        initial: getTrackerRequests(requests.initial),
        accepted: getTrackerRequests(requests.accepted),
        rejected: getTrackerRequests(requests.rejected),
    };
    console.log('Prevalence of Exodus-identified trackers in traffic:', {
        all: expandWithPercentages(tracker_requests.all.length, requests.all.length),
        initial: expandWithPercentages(tracker_requests.initial.length, requests.initial.length),
        accepted: expandWithPercentages(tracker_requests.accepted.length, requests.accepted.length),
        rejected: expandWithPercentages(tracker_requests.rejected.length, requests.rejected.length),
    });
    const apps_with_trackers = mapObject(tracker_requests, (type, reqs) => [
        type,
        reqs.reduce<Set<string>>((acc, r) => {
            acc.add(r.name);
            return acc;
        }, new Set()).size,
    ]);
    console.log('Apps with at least one Exodus-identified tracker:', {
        all: expandWithPercentages(apps_with_trackers.all, apps.all.length),
        initial: expandWithPercentages(apps_with_trackers.initial, apps.initial.length),
        accepted: expandWithPercentages(apps_with_trackers.accepted, apps.accepted.length),
        rejected: expandWithPercentages(apps_with_trackers.rejected, apps.rejected.length),
    });

    // Data types transmitted to trackers
    const all_requests_with_adapter = requests.all.filter((r) => adapterForRequest(r));
    console.log(
        `Total requests: ${requests.all.length}, requests with adapter: ${
            all_requests_with_adapter.length
        } (${percentage(all_requests_with_adapter.length, requests.all.length)})`
    );

    const data_type_replacers: Record<string, string> = {
        accelerometer_x: 'accelerometer',
        accelerometer_y: 'accelerometer',
        accelerometer_z: 'accelerometer',
        rotation_x: 'rotation',
        rotation_y: 'rotation',
        rotation_z: 'rotation',
        signal_strength_wifi: 'signal_strength',
        signal_strength_cellular: 'signal_strength',
        disk_total: 'disk_usage',
        disk_free: 'disk_usage',
        ram_total: 'ram_usage',
        ram_free: 'ram_usage',
        width: 'screen_size',
        height: 'screen_size',
        lat: 'location',
        long: 'location',
    };

    const computeAppData = (run_type: keyof typeof requests) => {
        // Maps from platform::app_id to a map from tracker to a map from data type to whether the data is transmitted
        // in conjunction with a unique ID (i.e. pseudonymously) or without (i.e. anonymously).
        const app_tracker_data: Record<string, Record<string, Record<string, 'pseudonymously' | 'anonymously'>>> = apps[
            run_type === 'initial' ? 'all' : run_type
        ].reduce<Record<string, {}>>((acc, cur) => ({ ...acc, [`${cur.platform}::${cur.name}`]: {} }), {});
        for (const r of requests[run_type]) {
            const app = `${r.platform}::${r.name}`;
            const adapter_data = processRequest(r);

            let data_types: string[];
            let tracker: string;

            // One of our adapters was able to process the request.
            if (adapter_data) {
                data_types = Object.entries(adapter_data)
                    .filter(([key]) => key !== 'tracker')
                    .flatMap(([_, d]) => Object.keys(d))
                    .map((t) => data_type_replacers[t] || t);

                tracker = adapter_data.tracker.name;
            }
            // None of our adapters could process the request, so we do indicator matching.
            else {
                data_types = Object.entries({ ...indicators, app_id: [r.name] })
                    .filter(([_, strings]) => requestHasIndicator(r, strings))
                    .map(([name]) => name);
                tracker = '<indicators>';
            }

            const is_pseudonymous = hasPseudonymousData(data_types);
            if (!app_tracker_data[app][tracker]) app_tracker_data[app][tracker] = {};
            for (const data_type of data_types)
                app_tracker_data[app][tracker][data_type] = is_pseudonymous
                    ? 'pseudonymously'
                    : app_tracker_data[app][tracker][data_type] || 'anonymously';
        }

        return app_tracker_data;
    };
    const app_tracker_data = {
        initial: computeAppData('initial'),
        accepted: computeAppData('accepted'),
        rejected: computeAppData('rejected'),
    };

    const appTransmitsPseudonymousData = (app: typeof app_tracker_data.initial[string]) =>
        Object.values(app)
            .map((d) => Object.keys(d))
            .some((s) => hasPseudonymousData(s));

    for (const run_type of Object.keys(app_tracker_data) as (keyof typeof app_tracker_data)[]) {
        await fs.writeFile(
            join(data_dir, `apps_trackers_data_types_${run_type}.json`),
            JSON.stringify(app_tracker_data[run_type], null, 4)
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
                [...Object.entries(data_types)].flatMap(([data_type, transmission_type]) => ({
                    app_id: app.split('::')[1],
                    tracker,
                    data_type,
                    transmission_type,
                    platform: app.split('::')[0] as 'android' | 'ios',
                }))
            )
        );
        await fs.writeFile(join(data_dir, `apps_trackers_data_types_${run_type}.csv`), Papa.unparse(csv_data));

        const csv_counts = csv_data.reduce<
            Record<
                string,
                {
                    tracker: string;
                    data_type: string;
                    platform: 'android' | 'ios';
                    transmission_type: 'pseudonymously' | 'anonymously';
                    count: number;
                }
            >
        >((acc, cur) => {
            const key = `${cur.platform}::${cur.tracker}::${cur.data_type}`;
            if (!acc[key])
                acc[key] = {
                    tracker: cur.tracker,
                    data_type: cur.data_type,
                    platform: cur.platform,
                    transmission_type: cur.transmission_type,
                    count: 0,
                };
            acc[key].count++;
            return acc;
        }, {});
        await fs.writeFile(
            join(data_dir, `apps_trackers_data_types_${run_type}_counts.csv`),
            Papa.unparse(Object.values(csv_counts))
        );
    }
};

const computePrivacyLabelData = async () => {
    const jsons = await Promise.all(
        glob
            .sync(join(argv.privacy_labels_dir, '*.json'), { absolute: true })
            .map(async (p) => JSON.parse(await fs.readFile(p, 'utf-8')))
    );
    const errors = jsons.filter((j) => j.errors || !j.data[0].attributes.privacyDetails);
    if (errors.length) {
        console.log(errors);
        throw new Error('Some app metadata has errors or no privacy labels.');
    }
    const all_privacy_labels = jsons
        .map((j) => j.data[0])
        .map((d) => ({
            app_id: z.string().parse(d.id),
            bundle_id: z.string().parse(d.attributes.platformAttributes.ios.bundleId),
            privacy_types: privacy_types_schema.parse(d.attributes.privacyDetails.privacyTypes),
        }));
    const empty_labels = all_privacy_labels.filter((p) => p.privacy_types.length === 0);
    console.log(
        empty_labels.length,
        'of',
        jsons.length,
        'apps',
        `(${percentage(empty_labels.length, jsons.length)})`,
        'have an empty privacy label.'
    );
    const privacy_labels = all_privacy_labels.filter((p) => p.privacy_types.length > 0);
    const no_data_labels = privacy_labels.filter(
        (a) => a.privacy_types.length === 1 && a.privacy_types[0].identifier === 'DATA_NOT_COLLECTED'
    );
    console.log(
        no_data_labels.length,
        'of',
        privacy_labels.length,
        `(${percentage(no_data_labels.length, privacy_labels.length)})`,
        'claim not to collect any data:',
        no_data_labels.map((d) => `${d.bundle_id} (${d.app_id})`).join(', ')
    );

    const app_tracker_data: Record<string, Record<string, string[]>> = JSON.parse(
        await fs.readFile(join(data_dir, 'apps_trackers_data_types_initial.json'), 'utf-8')
    );

    const ads_filter_list = await getFilterList('easylist');
    const tracking_filter_list = await getFilterList('easyprivacy');

    type TransmissionType = 'no' | 'anonymously' | 'pseudonymously';
    type DeclarationType =
        | 'correctly_declared'
        | 'correctly_undeclared'
        | 'wrongly_declared_as_anonymous'
        | 'wrongly_undeclared'
        | 'unnecessarily_declared'
        | 'unnecessarily_declared_as_pseudonymous';
    type DataTypeInstances = {
        data_type: string;
        our_data_types: Set<string>;
        transmitted: TransmissionType;
        declared: DeclarationType;
    }[];
    const data_type_instances: Record<string, DataTypeInstances> = {};
    const purpose_instances: Record<
        string,
        { tracking_used: boolean; tracking_declared: boolean; ads_used: boolean; ads_declared: boolean }
    > = {};
    for (const app of privacy_labels) {
        const { declared_pseudonymous, declared_anonymous } = app.privacy_types.reduce<{
            declared_pseudonymous: { purposes: Set<string>; data_types: Set<string> };
            declared_anonymous: { purposes: Set<string>; data_types: Set<string> };
        }>(
            (acc, cur) => {
                const purposes = cur.purposes.map((p) => p.purpose);
                const data_types = [
                    ...cur.dataCategories.flatMap((c) => c.dataTypes),
                    ...cur.purposes.flatMap((p) => p.dataCategories.flatMap((c) => c.dataTypes)),
                ].map((d) => (['Precise Location', 'Coarse Location'].includes(d) ? 'Location' : d));

                if (cur.identifier === 'DATA_NOT_COLLECTED' && (purposes.length > 0 || data_types.length > 0))
                    throw new Error('Label has "DATA_NOT_COLLECTED" but specifies data.');
                if (
                    ![
                        'DATA_NOT_LINKED_TO_YOU',
                        'DATA_NOT_COLLECTED',
                        'DATA_LINKED_TO_YOU',
                        'DATA_USED_TO_TRACK_YOU',
                    ].includes(cur.identifier)
                )
                    throw new Error('Unknown privacy type: ' + cur.identifier);

                for (const purpose of purposes)
                    (cur.identifier === 'DATA_NOT_LINKED_TO_YOU'
                        ? acc.declared_anonymous.purposes
                        : acc.declared_pseudonymous.purposes
                    ).add(purpose);
                for (const data_type of data_types)
                    (cur.identifier === 'DATA_NOT_LINKED_TO_YOU'
                        ? acc.declared_anonymous.data_types
                        : acc.declared_pseudonymous.data_types
                    ).add(data_type);

                return acc;
            },
            {
                declared_pseudonymous: { purposes: new Set(), data_types: new Set() },
                declared_anonymous: { purposes: new Set(), data_types: new Set() },
            }
        );

        const transmitted_data_per_tracker = app_tracker_data[`ios::${app.bundle_id}`];
        if (!transmitted_data_per_tracker) continue;
        for (const [pl_data_type, our_data_types] of Object.entries(privacy_label_data_type_mapping)) {
            const { transmitted, matched_data_types } = Object.values(transmitted_data_per_tracker).reduce<{
                transmitted: TransmissionType;
                matched_data_types: Set<string>;
            }>(
                (acc, transmitted_data_types) => {
                    const matched_data_types = our_data_types.filter((our_data_type) =>
                        transmitted_data_types.includes(our_data_type)
                    );

                    const tracker_received_data_in_pl = matched_data_types.length > 0;
                    const tracker_received_id = hasPseudonymousData(transmitted_data_types);

                    for (const data_type of matched_data_types) acc.matched_data_types.add(data_type);

                    if (tracker_received_data_in_pl && tracker_received_id) acc.transmitted = 'pseudonymously';
                    else if (tracker_received_data_in_pl && !tracker_received_id)
                        acc.transmitted = acc.transmitted === 'pseudonymously' ? 'pseudonymously' : 'anonymously';
                    return acc;
                },
                { transmitted: 'no', matched_data_types: new Set() }
            );

            const declared_label_pseudo = declared_pseudonymous.data_types.has(pl_data_type);
            const declared_label_ano = declared_anonymous.data_types.has(pl_data_type);

            const declared: DeclarationType = match(transmitted)
                .with('no', () =>
                    declared_label_ano || declared_label_pseudo ? 'unnecessarily_declared' : 'correctly_undeclared'
                )
                .with('anonymously', () =>
                    declared_label_ano
                        ? 'correctly_declared'
                        : declared_label_pseudo
                        ? 'unnecessarily_declared_as_pseudonymous'
                        : 'wrongly_undeclared'
                )
                .with('pseudonymously', () =>
                    declared_label_pseudo
                        ? 'correctly_declared'
                        : declared_label_ano
                        ? 'wrongly_declared_as_anonymous'
                        : 'wrongly_undeclared'
                )
                .exhaustive();

            if (!data_type_instances[app.bundle_id]) data_type_instances[app.bundle_id] = [];
            data_type_instances[app.bundle_id].push({
                data_type: pl_data_type,
                our_data_types: matched_data_types,
                transmitted,
                declared,
            });
        }

        const requests = await db.manyOrNone(
            "select host, endpoint_url from filtered_requests where name = ${bundle_id} and platform = 'ios';",
            { bundle_id: app.bundle_id }
        );
        const tracking_used = requests.some((r) => tracking_filter_list.includes(r.host));
        const tracking_declared =
            declared_pseudonymous.purposes.has('Analytics') || declared_anonymous.purposes.has('Analytics');
        const ads_used = requests.some((r) => ads_filter_list.includes(r.host));
        const ads_declared =
            declared_pseudonymous.purposes.has('Third-Party Advertising') ||
            declared_anonymous.purposes.has('Developer’s Advertising or Marketing');
        declared_pseudonymous.purposes.has('Third-Party Advertising') ||
            declared_anonymous.purposes.has('Developer’s Advertising or Marketing');
        purpose_instances[app.bundle_id] = {
            tracking_used,
            tracking_declared,
            ads_used,
            ads_declared,
        };
    }

    await fs.writeFile(join(data_dir, `privacy_label_types.json`), jsonify_obj_with_sets(data_type_instances));
    const data_type_instances_csv = Object.entries(data_type_instances).flatMap(([app, data]) =>
        data.map((entry) => ({ app, data_type: entry.data_type, declared: entry.declared }))
    );
    await fs.writeFile(join(data_dir, `privacy_label_types.csv`), Papa.unparse(data_type_instances_csv));

    await fs.writeFile(join(data_dir, `privacy_label_purposes.json`), jsonify_obj_with_sets(purpose_instances));
    const purpose_instances_csv = Object.entries(purpose_instances).flatMap(([app, data]) =>
        (['tracking', 'ads'] as const).map((type) => ({
            app,
            purpose: type,
            declared:
                !data[`${type}_used`] && !data[`${type}_declared`]
                    ? 'correctly_undeclared'
                    : !data[`${type}_used`] && data[`${type}_declared`]
                    ? 'unnecessarily_declared'
                    : data[`${type}_used`] && data[`${type}_declared`]
                    ? 'correctly_declared'
                    : 'wrongly_undeclared',
        }))
    );
    await fs.writeFile(join(data_dir, `privacy_label_purposes.csv`), Papa.unparse(purpose_instances_csv));
};

const computeCookieData = async () => {
    const cookie_db_csv = await fs.readFile(join(data_dir, 'upstream', 'open-cookie-database.csv'), 'utf-8');
    const cookie_db = Papa.parse<
        Record<
            | 'ID'
            | 'Platform'
            | 'Category'
            | 'Cookie / Data Key name'
            | 'Domain'
            | 'Description'
            | 'Retention period'
            | 'Data Controller'
            | 'User Privacy & GDPR Rights Portals'
            | 'Wildcard match',
            string
        >
    >(cookie_db_csv, { header: true, comments: '#' }).data;

    const platform_to_company: Record<string, string> = {
        'Google Analytics': 'Google',
        'Bing / Microsoft': 'Microsoft',
        Youtube: 'Google',
        'Adobe Analytics': 'Adobe',
        'Adobe Audience Manager': 'Adobe',
        'DoubleClick/Google Marketing': 'Google',
    };

    const cookies = (
        await Promise.all(
            Object.keys(cookie_regexes).map(
                async (cookie_name) =>
                    await db.manyOrNone<{
                        cookie_name: string;
                        cookie_value: string;
                        app_id: string;
                        platform: 'android' | 'ios';
                    }>(
                        'select cookies.name cookie_name, cookies.values[1] cookie_value, filtered_requests.name app_id, filtered_requests.platform platform from cookies join filtered_requests on cookies.request = filtered_requests.id where cookies.name=${cookie_name} group by cookie_name, cookie_value, app_id, platform',
                        { cookie_name }
                    )
            )
        )
    )
        .flat()
        .filter((c) => cookie_regexes[c.cookie_name as '_ga'].test(c.cookie_value))
        .map((c) => {
            const db_entry = cookie_db.find((e) => e['Cookie / Data Key name'] === c.cookie_name);
            return {
                ...c,
                category: db_entry?.Category,
                company: platform_to_company[db_entry?.Platform!] || db_entry?.Platform,
            };
        });
    await fs.writeFile(join(data_dir, `cookies.csv`), Papa.unparse(cookies));

    const cookie_counts = cookies.reduce<
        Record<string, { platform: 'android' | 'ios'; category: string; company: string; count: number }>
    >((acc, cur) => {
        const key = `${cur.platform}::${cur.category}::${cur.company}`;
        if (!acc[key])
            acc[key] = {
                platform: cur.platform,
                category: cur.category!,
                company: cur.company!,
                count: 0,
            };
        acc[key].count++;
        return acc;
    }, {});
    await fs.writeFile(join(data_dir, `cookie_counts.csv`), Papa.unparse(Object.values(cookie_counts)));
};

(async () => {
    if (argv.overview || argv.all) await printDialogAndViolationOverview();
    if (argv.dialog_data || argv.all) await computeDialogData();
    if (argv.tcf_data || argv.all) await computeTcfData();
    if (argv.request_data || argv.all) await computeRequestData();
    if (argv.privacy_label_data || argv.all) await computePrivacyLabelData();
    if (argv.cookie_data || argv.all) await computeCookieData();

    pg.end();
})();

process.on('unhandledRejection', (err) => {
    console.error('An unhandled promise rejection occurred:', err);
    pg.end();
    process.exit(1);
});
