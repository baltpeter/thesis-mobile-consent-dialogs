import { writeFileSync } from 'fs';
import { gunzipSync } from 'zlib';
import deepmerge from 'deepmerge';
import { match } from 'ts-pattern';
import { omit } from 'filter-anything';
import qs from 'qs';
import { PartialDeep } from 'type-fest';
import { db, pg } from './common/db.js';
import { base64_decode, concat, str2bool, remove_empty } from './common/util.js';

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
        idfa: string;
        idfv: string;
        hashed_adid: string;
        other_uuids: string[];
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
const getRequestsForEndpoint = (endpoint: string | RegExp) =>
    db.manyOrNone(
        "select * from (select *, regexp_replace(concat(r.scheme, '://', r.host, r.path), '\\?.+$', '') endpoint_url from requests r) t where " +
            (endpoint instanceof RegExp ? 'endpoint_url ~ ${endpoint};' : 'endpoint_url = ${endpoint};'),
        { endpoint: endpoint instanceof RegExp ? endpoint.source : endpoint }
    );

const adapters: {
    endpoint_urls: (string | RegExp)[];
    tracker: string;
    match?: (r: Request) => boolean | undefined;
    prepare: 'json_body' | 'qs_path' | 'qs_body' | PrepareFunction;
    extract: (pr: Record<string, any>) => TrackerDataResult;
}[] = [
    {
        endpoint_urls: [
            'https://live.chartboost.com/api/install',
            'https://live.chartboost.com/api/config',
            'https://live.chartboost.com/banner/show',
            'https://live.chartboost.com/webview/v2/prefetch',
            'https://live.chartboost.com/webview/v2/reward/get',
            'https://live.chartboost.com/webview/v2/interstitial/get',
            'https://da.chartboost.com/auction/sdk/banner',
        ],
        tracker: 'chartboost',
        prepare: (r) => {
            const json = JSON.parse(r.content!);
            if (
                [
                    'https://live.chartboost.com/webview/v2/prefetch',
                    'https://live.chartboost.com/webview/v2/reward/get',
                    'https://live.chartboost.com/webview/v2/interstitial/get',
                    'https://da.chartboost.com/auction/sdk/banner',
                ].includes(r.endpoint_url)
            )
                return { ...json.app, ...json.device, ...json.sdk, ...json.ad };
            return json;
        },
        extract: (pr) => ({
            app: {
                id: pr.bundle_id,
                version: pr.bundle,
            },
            tracker: {
                sdk_version: pr.sdk,
            },
            device: {
                idfa: pr.identity ? JSON.parse(base64_decode(pr.identity))?.gaid : undefined,
                other_uuids: [pr.session_id || pr.session_ID],
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
        extract: (pr) => ({
            app: {
                id: pr.application?.package || pr.application?.bundleIdentifier,
                version: pr.application?.versionName || pr.application?.bundleVersion,
            },
            tracker: {
                sdk_version: pr.library.libVersion,
            },
            device: {
                hashed_adid: pr.client.uuids.advertisingIdentifier, // md5(adid)
                other_uuids: [
                    pr.client.uuids.installationId,
                    pr.client.uuids.vendorIdentifier,
                    pr.client.uuids.androidId,
                ],
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
                other_uuids: [pr.clientSessionId],
                os: concat(pr.os, ['API level', pr.deviceVersion]),
                idfa: pr.userAdvertisingId,
                model: concat(pr.manufacturer, pr.model),
                language: pr.locale,
                width: pr.width,
                height: pr.height,
                roaming: str2bool(pr.roaming),
                uptime: pr.timeSinceBoot,
                rooted: str2bool(pr.root),
                orientation: pr.orientation,
                carrier: pr.ispName || pr.ispCarrIdName,
                ram_total: pr.usedRam + pr.freeRam,
                ram_free: pr.freeRam,
                network_connection_type: pr.grid,
                signal_strength_cellular: pr.cellSignalLevel,
                signal_strength_wifi: pr.wifiSignalLevel,
            },
        }),
    },
    {
        endpoint_urls: [
            /^https:\/\/(www|web)\.facebook\.com\/adnw_sync2$/,
            'https://graph.facebook.com/network_ads_common',
        ],
        tracker: 'facebook',
        prepare: (r) => {
            if (r.endpoint_url === 'https://graph.facebook.com/network_ads_common') return qs.parse(r.content!);
            const b = JSON.parse(qs.parse(r.content!).payload as string);
            // Sometimes, the data is directly on the object, other times it's in the `context` property.
            const b2: any = omit(deepmerge(b, b.context) as Record<string, unknown>, ['context']);
            return deepmerge(b2, {
                VALPARAMS: JSON.parse(b2.VALPARAMS || 'null'),
                ANALOG: JSON.parse(b2.ANALOG || 'null'),
            });
        },
        extract: (pr) => ({
            app: {
                id: pr.BUNDLE,
                version: pr.APPVERS,
            },
            device: {
                idfa: pr.IDFA,
                other_uuids: [pr.SESSION_ID, pr.ANON_ID],
                model: concat(pr.MAKE, pr.MODEL),
                emulator: str2bool(pr.VALPARAMS?.is_emu),
                rooted: str2bool(pr.ROOTED),
                carrier: pr.CARRIER,
                height: pr.SCREEN_HEIGHT,
                width: pr.SCREEN_WIDTH,
                os: concat(pr.OS, pr.OSVERS),
                is_charging: str2bool(pr.ANALOG?.charging),
                battery_percentage: pr.ANALOG?.battery,
                ram_total: pr.ANALOG?.total_memory,
                ram_free: pr.ANALOG?.available_memory,
                disk_free: pr.ANALOG?.free_space,
                accelerometer_x: pr.ANALOG?.accelerometer_x,
                accelerometer_y: pr.ANALOG?.accelerometer_y,
                accelerometer_z: pr.ANALOG?.accelerometer_z,
                rotation_x: pr.ANALOG?.rotation_x,
                rotation_y: pr.ANALOG?.rotation_y,
                rotation_z: pr.ANALOG?.rotation_z,
                language: pr.LOCALE,
            },
        }),
    },
    {
        endpoint_urls: [
            /^https:\/\/graph\.facebook\.com\/v\d{1,2}.\d$/,
            /^https:\/\/graph\.facebook\.com\/v\d{1,2}.\d\/\d+\/activities$/,
        ],
        match(r) {
            return r.content?.startsWith('{"') || r.content?.startsWith('format=json&');
        },
        tracker: 'facebook',
        prepare: (r) => {
            if (r.endpoint_url.endsWith('/activities')) {
                if (r.content?.startsWith('{')) return JSON.parse(r.content!);

                return qs.parse(r.content!);
            }

            const b = JSON.parse(r.content!);
            const batch = JSON.parse(b.batch).map((btch: { relative_url: string }) =>
                qs.parse(btch.relative_url.replace(/^.+?\?/, ''))
            );
            return { batch_app_id: b.batch_app_id, ...deepmerge.all(batch) };
        },
        extract: (pr) => ({
            app: {
                id: pr.application_package_name,
            },
            tracker: {
                sdk_version: pr.sdk_version,
            },
            device: {
                idfa: pr.advertiser_id,
                other_uuids: [pr.anon_id, pr.app_user_id],
                os: concat(pr.platform || pr.sdk, pr.os_version),
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
        extract: (pr) => ({
            app: {
                id: pr.bundleId,
            },
            device: {
                model: concat(pr.deviceMake, pr.deviceModel),
                idfa: pr.advertisingTrackingId,
                other_uuids: [pr.analyticsUserId],
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
            'https://cdp.cloud.unity3d.com/v1/events',
            'https://config.uca.cloud.unity3d.com/',
            'https://httpkafka.unityads.unity3d.com/v1/events',
            'https://thind.unityads.unity3d.com/v1/events',
        ],
        tracker: 'unity',
        // The bodies hold multiple events. We only support the first one, which is identified by the `common` property.
        prepare: (r) =>
            r
                .content!.split('\n')
                .filter((l) => l)
                .map((l) => JSON.parse(l))
                .find((o) => o.common)?.common,
        extract: (pr) => ({
            app: {
                id: pr.client?.bundleId || pr.storeId,
                version: pr.client?.bundleVersion,
            },
            tracker: {
                sdk_version: concat(pr.sdk_ver, pr.sdk_rev) || pr.adsSdkVersion,
            },
            device: {
                other_uuids: [pr.userid, pr.deviceid, pr.device_id, pr.analyticsUserId],
                model: concat(pr.device?.deviceMake, pr.device?.deviceModel) || concat(pr.deviceMake, pr.deviceModel),
                network_connection_type: pr.device?.connectionType || pr.connectionType,
                width: pr.device?.screenWidth,
                height: pr.device?.screenHeight,
                carrier: pr.device?.networkOperatorName,
                timezone: pr.device?.timeZone,
                language: pr.device?.language,
                volume: pr.device?.deviceVolume,
                disk_free: pr.device?.freeSpaceInternal,
                disk_total: pr.device?.totalSpaceInternal,
                battery_percentage: pr.device?.batteryLevel * 100,
                ram_free: pr.device?.freeMemory,
                ram_total: pr.device?.totalMemory,
                rooted: str2bool(pr.device?.rooted),
                user_agent: pr.device?.userAgent,
            },
            user: {
                country: pr.country,
            },
        }),
    },
    {
        endpoint_urls: [
            /https:\/\/app(\.eu)?\.adjust\.(com|net\.in|world)\/session/,
            /https:\/\/app(\.eu)?\.adjust\.(com|net\.in|world)\/attribution/,
            /https:\/\/app(\.eu)?\.adjust\.(com|net\.in|world)\/event/,
            /https:\/\/app(\.eu)?\.adjust\.(com|net\.in|world)\/sdk_click/,
            /https:\/\/app(\.eu)?\.adjust\.(com|net\.in|world)\/sdk_info/,
            /https:\/\/app(\.eu)?\.adjust\.(com|net\.in|world)\/third_party_sharing/,
            /https:\/\/app(\.eu)?\.adjust\.(com|net\.in|world)\/ad_revenue/,
            /https:\/\/app(\.eu)?\.adjust\.(com|net\.in|world)\/sdk_click/,
        ],
        tracker: 'adjust',
        prepare: (r) => {
            const b = qs.parse(r.endpoint_url.endsWith('/attribution') ? r.path : r.content!);
            return deepmerge(b, {
                ...(b.partner_params && { partner_params: JSON.parse(b.partner_params as string) }),
                ...(b.callback_params && { callback_params: JSON.parse(b.callback_params as string) }),
            });
        },
        extract: (pr) => ({
            app: {
                id: pr.package_name || pr.bundle_id,
                version: pr.app_version,
            },
            device: {
                idfa: pr.gps_adid || pr.idfa,
                idfv: pr.idfv,
                other_uuids: [pr.android_uuid, pr.ios_uuid, pr.fb_anon_id],
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
        extract: (pr) => ({
            app: {
                id: pr.device.appNamespace,
                version: pr.device.appVersion,
            },
            tracker: {
                sdk_version: pr.device.sdkVersion,
            },
            device: {
                other_uuids: [pr.sid, pr.userId],
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
        endpoint_urls: [
            'https://api.onesignal.com/players',
            'https://onesignal.com/api/v1/players',
            /https:\/\/api\.onesignal\.com\/players\/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}/,
        ],
        tracker: 'onesignal',
        prepare: (r) => {
            const player_id = r.path.match(
                /\/players\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/
            )?.[1];
            const b = r.content ? JSON.parse(r.content) : {};
            return { ...b, player_id };
        },
        extract: (pr) => ({
            tracker: {
                sdk_version: pr.sdk,
            },
            app: {
                id: pr.android_package || pr.ios_bundle || pr.app_id,
            },
            device: {
                idfa: pr.ad_id,
                other_uuids: [
                    pr.device?.device_id,
                    pr.identifier,
                    pr.external_user_id,
                    pr.tags?.device_id,
                    pr.player_id,
                ],
                os: concat(pr.device_os),
                timezone: pr.timezone_id,
                model: pr.device_model,
                carrier: pr.carrier,
                rooted: str2bool(pr.rooted),
                language: pr.language || pr.tags?.lang || pr.tags?.language,
                name: pr.device?.deviceName,
            },
            user: {
                lat: pr.lat,
                long: pr.long,
            },
        }),
    },
    {
        endpoint_urls: ['https://outcome-ssp.supersonicads.com/mediation', 'TODO'],
        tracker: 'supersonic',
        prepare: (r) => {
            let blob: string;
            try {
                blob = r.content?.startsWith('{"')
                    ? r.content
                    : gunzipSync(Buffer.from(r.content!, 'base64')).toString('utf-8');
            } catch {
                return {};
            }
            const json = JSON.parse(blob);
            const query = qs.parse(r.path.replace(/.+\?/, ''));
            if (json.table && json.data) return { table: json.table, ...JSON.parse(json.data), ...query };
            return { ...json, ...query };
        },
        extract: (pr) => ({
            app: {
                version: pr.appVersion,
                id: pr.bundleId,
            },
            device: {
                carrier: pr.mobileCarrier,
                timezone: pr.tz,
                idfa: pr.advertisingId,
                idfv: pr.idfv,
                other_uuids: [pr.sessionId, pr.userId],
                language: pr.language,
                battery_percentage: pr.battery,
                network_connection_type: pr.connectionType,
                ram_free: pr.internalFreeMemory,
                os: concat(pr.deviceOS, pr.osVersion?.match(/\d+\((\d+)\)/)?.[1]),
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
                idfa: pr.advertiser_id,
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
                idfa: pr.advertiser_id,
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
                idfa: pr.consent_ifa || (pr.udid?.startsWith('ifa:') ? pr.udid : undefined),
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
                idfa: pr.google_advertising_id || pr.advertising_ids?.aaid,
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
                idfa: pr.ifa,
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
                idfa: pr.device?.ifa || pr.device?.ext?.vungle?.android?.gaid,
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
                idfa: pr.adv_id,
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
            return r.method === 'POST';
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
                idfa: pr.gaid || pr.data?.gaid,
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
                idfa: pr.data?.applicationuserid || pr.data?.deviceid,
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
        await Promise.all(
            adapters.find((a) => a.endpoint_urls.includes('TODO'))!.endpoint_urls.map((e) => getRequestsForEndpoint(e))
        )
    ).flat();

    const prepared_requests_for_debugging: any[] = [];
    const results = requests.map((r) => {
        const adapter = adapters.find(
            (a) =>
                a.endpoint_urls.some((url) =>
                    url instanceof RegExp ? url.test(r.endpoint_url) : url === r.endpoint_url
                ) && (a.match ? a.match(r) : true)
        );
        if (!adapter) return -1; // TODO

        const prepared_request = match(adapter.prepare)
            .when(
                (x): x is PrepareFunction => typeof x === 'function',
                (x) => x(r)
            )
            .with('json_body', () => (r.content ? JSON.parse(r.content) : {}))
            .with('qs_path', () => qs.parse(r.path.replace(/.+\?/, '')))
            .with('qs_body', () => qs.parse(r.content!))
            .exhaustive();
        prepared_requests_for_debugging.push(prepared_request);

        // TODO: v
        const res = adapter.extract(prepared_request);
        // const res = remove_empty(adapter.extract(prepared_request));
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
