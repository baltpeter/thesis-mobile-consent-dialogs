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
        name: string;
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
        name: string;
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
        mac_address: string;
        architecture: string;
        dark_mode: boolean;
        local_ips: string[];
        volume: number;
    };
    user: {
        country: string;
        lat: number;
        long: number;
        public_ip: string;
    };
}>;

// TODO: This is only for developing the adapters. In the end, we will match on an individual request and need to
// identify the correct endpoint ourselves.
const getRequestsForEndpoint = (endpoint: string) =>
    db.many(
        "select * from (select *, regexp_replace(concat(r.scheme, '://', r.host, r.path), '\\?.+$', '') endpoint_url from requests r) t where endpoint_url = ${endpoint};",
        { endpoint }
    );

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
    {
        endpoint_urls: ['https://outcome-ssp.supersonicads.com/mediation'],
        tracker: 'supersonic',
        // TODO: Deal with the ones with base64 blob.
        match(r) {
            return (this.endpoint_urls.includes(r.endpoint_url) && r.content?.startsWith('{"')) || false;
        },
        prepare: (r) => {
            const json = JSON.parse(r.content!);
            const query = qs.parse(r.path.replace(/.+\?/, ''));
            if (json.table && json.data) return { table: json.table, ...JSON.parse(json.data), ...query };
            return { ...json, ...query };
        },
        // TODO: icc, mcc, firstSession, auid, mnc, mt, sessionId, abt, groupId*, internalTestId, adUnit, events, InterstitialEvents, user_id
        extract: (pr) => ({
            app: {
                version: pr.appVersion,
                id: pr.bundleId,
            },
            device: {
                carrier: pr.mobileCarrier,
                timezone: pr.tz,
                adid: pr.advertisingId,
                language: pr.language,
                battery_percentage: pr.battery,
                network_connection_type: pr.connectionType,
                ram_free: pr.internalFreeMemory,
                os: concat(pr.deviceOS, pr.osVersion.match(/\d+\((\d+)\)/)[1]),
                model: concat(pr.deviceOEM, pr.deviceModel),
                rooted: str2bool(pr.jb),
            },
            tracker: {
                sdk_version: pr.sdkVersion,
            },
        }),
    },
    {
        endpoint_urls: ['https://adc3-launch.adcolony.com/v4/launch'],
        tracker: 'adcolony',
        prepare: 'json_body',
        // TODO: device_type, *_path, memory_class, memory_used, cleartext_permitted, available_stores, adc_alt_id, network_speed, launch_metadata, permissions, device_id, immersion
        extract: (pr) => ({
            device: {
                carrier: pr.carrier_name,
                width: pr.screen_width,
                height: pr.screen_height,
                language: pr.locale_language_code,
                mac_address: pr.mac_address,
                model: concat(pr.manufacturer || pr.device_brand, pr.model || pr.device_model),
                network_connection_type: pr.network_type,
                os: concat(pr.os_name || pr.platform, pr.os_version),
                architecture: pr.arch,
                battery_percentage: pr.battery_level,
                timezone: pr.timezone_ietf,
                orientation: pr.current_orientation === 0 ? 'portrait' : 'landscape',
                dark_mode: str2bool(pr.dark_mode),
                adid: pr.advertiser_id,
            },
            tracker: {
                sdk_version: pr.sdk_version,
            },
            app: {
                name: pr.app_bundle_name,
                version: pr.app_bundle_version,
            },
        }),
    },
    {
        endpoint_urls: ['https://androidads4-6.adcolony.com/configure'],
        tracker: 'adcolony',
        prepare: 'json_body',
        // TODO: origin_store, mediation_network, *_path, device_type, adc_alt_id, zones, ad_history, ad_playing, ad_queue, sid, memory_used_mb, available_stores, device_audio
        extract: (pr) => ({
            app: {
                id: pr.bundle_id,
                version: pr.bundle_version_short,
            },
            device: {
                os: concat(pr.os_name, pr.os_version),
                adid: pr.advertiser_id,
                carrier: pr.carrier,
                language: pr.ln,
                model: concat(pr.device_brand || pr.manufacturer, pr.device_model),
                battery_percentage: pr.battery_level,
                orientation: pr.current_orientation === 0 ? 'portrait' : 'landscape',
                timezone: pr.timezone_ietf,
                height: pr.screen_height,
                width: pr.screen_width,
            },
            tracker: {
                sdk_version: pr.sdk_version,
            },
        }),
    },
    {
        endpoint_urls: ['https://ads.mopub.com/m/open', 'https://ads.mopub.com/m/gdpr_sync'],
        tracker: 'mopub',
        prepare: 'json_body',
        // Key documentation: https://github.com/mopub/mopub-ios-sdk/blob/4b5e70e4ff69b0c3f4ab71a8791f5e7351ad2828/MoPubSDK/Internal/MPAdServerKeys.m
        // TODO: tas (tracking authorization status, #L18), adunit, e_name, last_consent_status, consent_change_reason
        extract: (pr) => ({
            app: {
                version: pr.av, // #L14
                id: pr.bundle,
            },
            tracker: {
                sdk_version: pr.nv, // #L19
            },
            device: {
                adid: pr.consent_ifa || (pr.udid?.startsWith('ifa:') ? pr.udid : undefined),
                os: concat(pr.os, pr.osv),
                model: concat(pr.make, pr.model),
                name: pr.dn, // #L24
            },
        }),
    },
    {
        endpoint_urls: ['https://api2.branch.io/v1/install'],
        tracker: 'branchio',
        prepare: 'json_body',
        // TODO: hardware_id, ui_mode, facebook_app_link_checked, is_referrable, *_install_time, environment, metadata, branch_key, partner_data, initial_referrer
        extract: (pr) => ({
            device: {
                model: concat(pr.brand, pr.model),
                width: pr.screen_width,
                height: pr.screen_height,
                network_connection_type: pr.connection_type,
                os: concat(pr.os, pr.os_version_android, ['API level:', pr.os_version]),
                language: pr.language,
                local_ips: [pr.local_ip],
                adid: pr.google_advertising_id || pr.advertising_ids?.aaid,
                architecture: pr.cpu_type,
                carrier: pr.device_carrier,
            },
            user: {
                country: pr.country,
            },
            app: {
                version: pr.app_version,
                id: pr.cd?.pn,
            },
            tracker: {
                sdk_version: pr.sdk,
            },
        }),
    },
    {
        endpoint_urls: ['https://api.vungle.com/api/v5/new'],
        tracker: 'vungle',
        prepare: 'qs_path',
        // TODO: app_id (is sometimes (but usually not) the bundle ID)
        extract: (pr) => ({
            device: {
                adid: pr.ifa,
            },
        }),
    },
    {
        endpoint_urls: [
            'https://ads.api.vungle.com/config',
            'https://api.vungle.com/api/v5/ads',
            'https://events.api.vungle.com/api/v5/cache_bust',
        ],
        tracker: 'vungle',
        prepare: 'json_body',
        // TODO: is_google_play_services_available, battery_saver_enabled, data_saver_status, network_metered, sound_enabled, is_sideload_enabled, sd_card_available, lmt, vision, request
        extract: (pr) => ({
            device: {
                model: concat(pr.device?.make, pr.device?.model),
                os: concat(pr.device?.os, pr.device?.osv),
                carrier: pr.device?.carrier,
                width: pr.device?.w,
                height: pr.device?.h,
                adid: pr.device?.ifa || pr.device?.ext?.vungle?.android?.gaid,
                battery_percentage: pr.device?.ext?.vungle?.android?.battery_level,
                is_charging: pr.device?.ext?.vungle?.android?.battery_state === 'NOT_CHARGING' ? false : true,
                network_connection_type: pr.device?.ext?.vungle?.android?.connection_type,
                language: pr.device?.ext?.vungle?.android?.language,
                timezone: pr.device?.ext?.vungle?.android?.time_zone,
                volume: pr.device?.ext?.vungle?.android?.volume_level,
                disk_free: pr.device?.ext?.vungle?.android?.storage_bytes_available,
                user_agent: pr.device?.ua,
            },
            app: {
                id: pr.app?.bundle,
                version: pr.app?.ver,
            },
        }),
    },
    {
        endpoint_urls: [
            'https://startup.mobile.yandex.net/analytics/startup',
            'https://report.appmetrica.yandex.net/report',
        ],
        tracker: 'yandex',
        prepare: 'qs_path',
        // TODO: deviceid, deviceid2, device_type, features, uuid
        extract: (pr) => ({
            device: {
                adid: pr.adv_id,
                os: concat(pr.app_platform, pr.os_version),
                model: concat(pr.manufacturer, pr.model),
                width: pr.screen_width,
                height: pr.screen_height,
                language: pr.locale?.split('_')[0],
                rooted: str2bool(pr.is_rooted),
            },
            tracker: {
                sdk_version: pr.analytics_sdk_version_name,
            },
            app: {
                id: pr.app_id,
                version: pr.app_version_name,
            },
        }),
    },
    {
        endpoint_urls: ['https://sessions.bugsnag.com/'],
        tracker: 'bugsnag',
        match(r) {
            return this.endpoint_urls.includes(r.endpoint_url) && r.method === 'POST';
        },
        prepare: 'json_body',
        // TODO: locationStatus, sessions
        extract: (pr) => ({
            tracker: {
                sdk_version: pr.notifier?.version,
            },
            app: {
                version: pr.app?.version,
                id: pr.app?.id || pr.app?.packageName,
                in_foreground: str2bool(pr.app?.inForeground),
                viewed_page: pr.app?.activeScreen,
            },
            device: {
                architecture: pr.device?.cpuAbi,
                os: concat(pr.device?.osName, pr.device?.osVersion, [pr.device?.osBuild]),
                rooted: str2bool(pr.device?.jailbroken),
                model: concat(pr.device?.manufacturer || pr.device?.brand, pr.device?.model),
                language: pr.device?.locale?.split('_')[0],
                user_agent: pr.device?.userAgent,
                orientation: pr.device?.orientation,
                ram_total: pr.device?.totalMemory,
                timezone: pr.device?.timezone,
                is_charging: str2bool(pr.device?.charging),
                disk_free: pr.device?.freeDisk,
                network_connection_type: pr.device?.networkAccess,
                emulator: str2bool(pr.device?.emulator),
                height: pr.device?.screenResolution?.split('x')[0],
                width: pr.device?.screenResolution?.split('x')[1],
                ram_free: pr.device?.freeMemory,
                battery_percentage: pr.device?.batteryLevel,
            },
        }),
    },
    {
        endpoint_urls: ['https://configure.rayjump.com/setting', 'https://analytics.rayjump.com/'],
        tracker: 'rayjump',
        prepare: (r) => {
            if (r.endpoint_url === 'https://configure.rayjump.com/setting') return qs.parse(r.path.replace(/.+\?/, ''));

            const json = qs.parse(decodeURIComponent(r.content!)) as Record<string, any>;
            return deepmerge(json, { data: qs.parse(json.data) });
        },
        // TODO: sign, open, channel, band_width, platform, network_type, st
        extract: (pr) => ({
            device: {
                os: concat(pr.os || pr.db, pr.os_version || pr.osv),
                orientation: pr.orientation && pr.orientation === '1' ? 'portrait' : 'landscape' || undefined,
                model: concat(pr.brand, pr.model),
                adid: pr.gaid || pr.data?.gaid,
                language: pr.language,
                timezone: pr.timezone,
                user_agent: pr.useragent || pr.ua?.replace('+', ' '),
                width: pr.screen_size?.split('x')[0],
                height: pr.screen_size?.split('x')[1],
            },
            app: {
                id: pr.package_name || pr.pn,
                version: pr.app_version_name,
            },
            tracker: {
                sdk_version: pr.sdk_version,
            },
            user: {
                country: pr.ct || pr.country_code,
                public_ip: pr.ip,
            },
        }),
    },
    {
        endpoint_urls: ['https://logs.ironsrc.mobi/logs'],
        tracker: 'ironsource',
        prepare: (r) => JSON.parse(base64_decode((qs.parse(r.path.replace(/.+\?/, '')) as { data: string }).data)),
        extract: (pr) => ({
            device: {
                model: concat(pr.data?.deviceoem, pr.data?.devicemodel),
                os: concat(pr.data?.deviceos, pr.data?.deviceosversion, ['API level:', pr.data?.deviceapilevel]),
                adid: pr.data?.applicationuserid || pr.data?.deviceid,
                network_connection_type: pr.data?.connectiontype,
            },
            app: {
                id: pr.data?.bundleid,
                version: pr.data?.appversion,
            },
            tracker: {
                sdk_version: pr.data?.sdkversion,
            },
        }),
    },
];

async function main() {
    const requests: Request[] = (
        await Promise.all(['https://logs.ironsrc.mobi/logs'].map((e) => getRequestsForEndpoint(e)))
    ).flat();

    const prepared_requests_for_debugging: any[] = [];
    const results = requests.map((r) => {
        const adapter = adapters.find((a) => (a.match ? a.match(r) : a.endpoint_urls.includes(r.endpoint_url)));
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
        return deepmerge({ tracker: { name: adapter.tracker, endpoint_url: r.endpoint_url } }, res);
    });
    console.dir(results, { depth: null });
    writeFileSync('./merged-reqs.tmp.json', JSON.stringify(deepmerge.all(prepared_requests_for_debugging), null, 4));

    pg.end();
}

process.on('unhandledRejection', (err) => {
    console.error('An unhandled promise rejection occurred:', err);

    pg.end();
    process.exit(1);
});

main();
