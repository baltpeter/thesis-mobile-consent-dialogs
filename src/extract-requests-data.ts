import { writeFileSync } from 'fs';
import deepmerge from 'deepmerge';
import { match } from 'ts-pattern';
import qs from 'qs';
import { PartialDeep } from 'type-fest';
import { db, pg } from './common/db.js';
import { base64_decode, concat, str2bool } from './common/util.js';

type Request = {
    id: number;
    run: number;
    start_time: Date;
    method: 'OPTIONS' | 'PATCH' | 'GET' | 'PRI' | 'HEAD' | 'POST' | 'PUT' | 'DELETE';
    host: string;
    path: string;
    endpoint_url: string;
    content?: string;
    content_raw?: Buffer;
    port: number;
    scheme: 'http' | 'https';
    authority: string;
    http_version: 'HTTP/1.0' | 'HTTP/1.1' | 'HTTP/2.0';
};
type PrepareFunction = (r: Request) => Record<string, any>;
type TrackerDataResult = PartialDeep<{
    app: {
        id: string;
        version: string;
        viewed_page: string;
        in_foreground: boolean;
    };
    tracker: {
        sdk_version: string;
    };
    device: {
        adid: string;
        model: string;
        os: string;
        language: string;
        timezone: string;
        user_agent: string;
        orientation: 'portrait' | 'landscape';
        carrier: string;
        rooted: boolean;
        emulator: boolean;
        width: number;
        height: number;
        roaming: boolean;
        uptime: number;
        ram_total: number;
        ram_free: number;
        network_connection_type: string;
        signal_strength_cellular: number;
        signal_strength_wifi: number;
        is_charging: boolean;
        battery_percentage: number;
        disk_total: number;
        disk_free: number;
        accelerometer_x: number;
        accelerometer_y: number;
        accelerometer_z: number;
        rotation_x: number;
        rotation_y: number;
        rotation_z: number;
    };
    user: {
        country: string;
        lat: number;
        long: number;
    };
}>;

// TODO: This is only for developing the adapters. In the end, we will match on an individual request and need to
// identify the correct endpoint ourselves.
const getRequestsForEndpoint = (endpoint: string) =>
    db.many(
        "select * from (select *, regexp_replace(concat(r.scheme, '://', r.host, r.path), '\\?.+$', '') endpoint_url from requests r) t where endpoint_url = ${endpoint};",
        { endpoint }
    );

const getEndpointUrlForRequest = (r: Request) => `${r.scheme}://${r.host}${r.path.replace(/\?.+$/, '')}`;

const adapters: {
    endpoint_urls: string[];
    tracker: string;
    match?: (r: Request) => boolean;
    prepare: 'json_body' | 'qs_path' | 'qs_body' | PrepareFunction;
    extract: (pr: Record<string, any>) => TrackerDataResult;
}[] = [
    {
        endpoint_urls: ['https://live.chartboost.com/api/install', 'https://live.chartboost.com/api/config'],
        tracker: 'chartboost',
        prepare: 'json_body',
        // TODO: session, reachability, mobile_network, certification_providers, mediation
        extract: (pr) => ({
            app: {
                id: pr.bundle_id,
                version: pr.bundle,
            },
            tracker: {
                sdk_version: pr.sdk,
            },
            device: {
                adid: JSON.parse(base64_decode(pr.identity))?.gaid,
                model: pr.device_type,
                os: pr.os,
                language: pr.language,
                timezone: pr.timezone,
                user_agent: pr.user_agent,
                orientation: pr.is_portrait !== undefined ? (pr.is_portrait ? 'portrait' : 'landscape') : undefined,
                carrier: pr.carrier['carrier-name'],
                rooted: str2bool(pr.rooted_device),
                width: pr.dw,
                height: pr.dh,
                network_connection_type: match(pr.mobile_network)
                    .with(1, () => 'cellular')
                    .with(0, () => 'wifi')
                    .otherwise(() => undefined),
            },
            user: {
                country: pr.country,
            },
        }),
    },
    {
        endpoint_urls: ['https://config.ioam.de/appcfg.php'],
        tracker: 'ioam',
        prepare: 'json_body',
        // TODO: client.{uuids,network}
        extract: (pr) => ({
            app: {
                id: pr.application?.package,
                version: pr.application?.versionName,
            },
            tracker: {
                sdk_version: pr.library.libVersion,
            },
            device: {
                model: pr.client.platform,
                os: concat(pr.client.osIdentifier, pr.client.osVersion),
                language: pr.client.language,
                carrier: pr.client.carrier,
                width: pr.client.screen.resolution.split('x')[0],
                height: pr.client.screen.resolution.split('x')[1],
            },
            user: {
                country: pr.client.country,
            },
        }),
    },
    // {
    //     endpoint_urls: ['https://api.segment.io/v1/import'],
    //     tracker: 'segment',
    //     prepare: (r) => deepmerge.all(JSON.parse(r.content!).batch),
    //     extract: (pr) => ({}),
    // },
    {
        endpoint_urls: [
            'https://infoevent.startappservice.com/tracking/infoEvent',
            'https://infoevent.startappservice.com/infoevent/api/v1.0/info',
            'https://trackdownload.startappservice.com/trackdownload/api/1.0/trackdownload',
        ],
        tracker: 'startio',
        prepare: (r) =>
            r.endpoint_url === 'https://trackdownload.startappservice.com/trackdownload/api/1.0/trackdownload'
                ? qs.parse(r.path!.replace(/.+\?/, ''))
                : JSON.parse(r.content!),
        // TODO: flavor, outsource, fgApp, clientSessionId, appCode, udbg, smltr, isddbg, tsh, category, value, details, cellScanRes, cid, lac, pas, isService, prm, placement
        extract: (pr) => ({
            app: {
                id: pr.packageId,
                version: pr.appVersion,
                viewed_page: pr.appActivity,
                in_foreground: str2bool(pr.fgApp),
            },
            tracker: {
                sdk_version: pr.sdkVersion,
            },
            device: {
                os: concat(pr.os, ['API level', pr.deviceVersion]),
                adid: pr.userAdvertisingId,
                model: concat(pr.manufacturer, pr.model),
                language: pr.locale,
                width: pr.width,
                height: pr.height,
                roaming: str2bool(pr.roaming),
                uptime: pr.timeSinceBoot,
                rooted: str2bool(pr.root),
                orientation: pr.orientation,
                carrier: pr.ispName,
                ram_total: pr.usedRam + pr.freeRam,
                ram_free: pr.freeRam,
                network_connection_type: pr.grid,
                signal_strength_cellular: pr.cellSignalLevel,
                signal_strength_wifi: pr.wifiSignalLevel,
            },
        }),
    },
    {
        endpoint_urls: ['https://www.facebook.com/adnw_sync2', 'https://graph.facebook.com/network_ads_common'],
        tracker: 'facebook',
        prepare: (r) => {
            if (r.endpoint_url === 'https://graph.facebook.com/network_ads_common') return qs.parse(r.content!);
            const b = JSON.parse(qs.parse(r.content!).payload as string);
            return deepmerge(b, {
                context: { VALPARAMS: JSON.parse(b.context.VALPARAMS), ANALOG: JSON.parse(b.context.ANALOG) },
            });
        },
        // TODO: request, KG_RESTRICTED, app_started_reason, UNITY, ACCESSIBILITY_ENABLED, HAS_EXOPLAYER, AFP, CLIENT_REQUEST_ID, FUNNEL_CORE_EVENTS, ASHAS, NETWORK_TYPE, RTF_FB_APP_INSTALLED, SESSION_ID, MEDIATION_SERVICE
        extract: (pr) => ({
            app: {
                id: pr.context.BUNDLE,
                version: pr.context.APPVERS,
            },
            device: {
                model: concat(pr.context.MAKE, pr.context.MODEL),
                emulator: str2bool(pr.context.VALPARAMS.is_emu),
                rooted: str2bool(pr.context.ROOTED),
                carrier: pr.context.CARRIER,
                height: pr.context.SCREEN_HEIGHT,
                width: pr.context.SCREEN_WIDTH,
                os: concat(pr.context.OS, pr.context.OSVERS),
                is_charging: str2bool(pr.context.ANALOG.charging),
                battery_percentage: pr.context.ANALOG.battery,
                ram_total: pr.context.ANALOG.total_memory,
                ram_free: pr.context.ANALOG.available_memory,
                disk_free: pr.context.ANALOG.free_space,
                accelerometer_x: pr.context.ANALOG.accelerometer_x,
                accelerometer_y: pr.context.ANALOG.accelerometer_y,
                accelerometer_z: pr.context.ANALOG.accelerometer_z,
                rotation_x: pr.context.ANALOG.rotation_x,
                rotation_y: pr.context.ANALOG.rotation_y,
                rotation_z: pr.context.ANALOG.rotation_z,
                language: pr.context.LOCALE,
                adid: pr.context.IDFA,
            },
        }),
    },
    {
        endpoint_urls: [
            'https://publisher-config.unityads.unity3d.com/games/3268074/configuration',
            'https://auction.unityads.unity3d.com/v4/test/games/3268074/requests',
        ],
        tracker: 'unity',
        prepare: 'qs_path',
        // TODO: idfi, encrypted, analyticsSessionId, first, analyticsUserId, stores, networkType
        extract: (pr) => ({
            app: {
                id: pr.bundleId,
            },
            device: {
                model: concat(pr.deviceMake, pr.deviceModel),
                adid: pr.advertisingTrackingId,
                network_connection_type: pr.connectionType,
                width: pr.screenWidth,
                height: pr.screenHeight,
                rooted: str2bool(pr.rooted),
                os: concat(pr.platform, pr.osVersion),
                language: pr.language,
            },
        }),
    },
    {
        endpoint_urls: [
            'https://app.adjust.com/session',
            'https://app.adjust.com/attribution',
            'https://app.adjust.com/event',
        ],
        tracker: 'adjust',
        prepare: (r) => {
            const b = qs.parse(r.content!);
            return deepmerge(b, {
                ...(b.partner_params && { partner_params: JSON.parse(b.partner_params as string) }),
                ...(b.callback_params && { callback_params: JSON.parse(b.callback_params as string) }),
            });
        },
        // TODO: gps_adid_attempt, partner_params, callback_params, hardware_name, installed_at, connectivity_type, mcc, os_build, cpu_type, mnc,android_uuid, session_count, network_type, ui_mode, time_spent, revenue?, currency?
        extract: (pr) => ({
            app: {
                id: pr.package_name,
                version: pr.app_version,
            },
            device: {
                adid: pr.gps_adid,
                language: pr.language,
                model: concat(pr.device_manufacturer, pr.device_name),
                width: pr.display_width,
                height: pr.display_height,
                os: concat(pr.os_name, pr.os_version, ['build', pr.os_build]),
            },
            user: {
                country: pr.country,
            },
        }),
    },
    {
        endpoint_urls: ['https://in.appcenter.ms/logs'],
        tracker: 'ms_appcenter',
        prepare: (r) => deepmerge.all(JSON.parse(r.content!).logs),
        // TODO: type, sid, actual event data, userId
        extract: (pr) => ({
            app: {
                id: pr.device.appNamespace,
                version: pr.device.appVersion,
            },
            tracker: {
                sdk_version: pr.device.sdkVersion,
            },
            device: {
                model: concat(pr.device.oemName, pr.device.model),
                os: concat(pr.device.osName, pr.device.osVersion, ['build', pr.device.osBuild]),
                language: pr.device.locale,
                timezone: pr.device.timeZoneOffset,
                width: pr.device.screenSize?.split('x')[0],
                height: pr.device.screenSize?.split('x')[1],
                carrier: pr.device.carrierName,
            },
        }),
    },
    {
        endpoint_urls: ['https://api.onesignal.com/players'],
        tracker: 'onesignal',
        prepare: 'json_body',
        // TODO: game_version, net_type, device_type, notification_types, identifier, external_user_id
        extract: (pr) => ({
            tracker: {
                sdk_version: pr.sdk,
            },
            app: {
                id: pr.android_package,
            },
            device: {
                adid: pr.ad_id,
                os: concat(pr.device_os),
                timezone: pr.timezone_id,
                model: pr.device_model,
                carrier: pr.carrier,
                rooted: str2bool(pr.rooted),
                language: pr.tags?.lang,
            },
            user: {
                lat: pr.lat,
                long: pr.long,
            },
        }),
    },
];

async function main() {
    const requests: Request[] = (
        await Promise.all(['https://api.onesignal.com/players'].map((e) => getRequestsForEndpoint(e)))
    ).flat();

    const prepared_requests_for_debugging: any[] = [];
    const results = requests.map((r) => {
        const adapter = adapters.find((a) =>
            a.match ? a.match(r) : a.endpoint_urls.includes(getEndpointUrlForRequest(r))
        );
        if (!adapter) return -1; // TODO

        const prepared_request = match(adapter.prepare)
            .when(
                (x): x is PrepareFunction => typeof x === 'function',
                (x) => x(r)
            )
            .with('json_body', () => JSON.parse(r.content!))
            .with('qs_path', () => qs.parse(r.path.replace(/.+\?/, '')))
            .with('qs_body', () => qs.parse(r.content!))
            .exhaustive();
        prepared_requests_for_debugging.push(prepared_request);

        const res = adapter.extract(prepared_request);
        return deepmerge({ tracker: { name: adapter.tracker, endpoint_url: getEndpointUrlForRequest(r) } }, res);
    });
    console.log(results);
    writeFileSync('./merged-reqs.tmp.json', JSON.stringify(deepmerge.all(prepared_requests_for_debugging), null, 4));

    pg.end();
}

process.on('unhandledRejection', (err) => {
    console.error('An unhandled promise rejection occurred:', err);

    pg.end();
    process.exit(1);
});

main();
