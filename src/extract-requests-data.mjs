import deepmerge from 'deepmerge';
import { match, when, otherwise, isFunction } from 'match-iz';
import { db, pg } from './common/db.mjs';
import { base64_decode } from './common/util.mjs';

// TODO: This is only for developing the adapters. In the end, we will match on an individual request and need to
// identify the correct endpoint ourselves.
const getRequestsForEndpoint = (endpoint) =>
    db.many(
        "select * from requests r where regexp_replace(concat(r.scheme, '://', r.host, r.path), '\\?.+$', '') = ${endpoint};",
        { endpoint }
    );

const getEndpointUrlForRequest = (r) => `${r.scheme}://${r.host}${r.path}`;

const adapters = [
    {
        endpoint_urls: ['https://live.chartboost.com/api/install', 'https://live.chartboost.com/api/config'],
        tracker: 'chartboost',
        prepare: 'json_body',
        // TODO: session, reachability, scale, mobile_network, certification_providers
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
                rooted: pr.rooted_device,
                width: pr.dw,
                height: pr.dh,
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
                os: `${pr.client.osIdentifier} ${pr.client.osVersion}`,
                language: pr.client.language,
                carrier: pr.client.carrier,
                width: pr.client.screen.resolution.split('x')[0],
                width: pr.client.screen.resolution.split('x')[1],
            },
            user: {
                country: pr.client.country,
            },
        }),
    },
];

async function main() {
    const requests = await getRequestsForEndpoint('https://config.ioam.de/appcfg.php');

    const results = requests.map((r) => {
        const adapter = adapters.find((a) =>
            a.match ? a.match(r) : a.endpoint_urls.includes(getEndpointUrlForRequest(r))
        );
        if (!adapter) return -1; // TODO
        const prepared_request = match(adapter.prepare)(
            when(isFunction)(() => adapter.prepare(r)),
            when('json_body')(JSON.parse(r.content)),
            otherwise(r)
        );
        const res = adapter.extract(prepared_request);
        return deepmerge({ tracker: { name: adapter.tracker, endpoint_url: getEndpointUrlForRequest(r) } }, res);
    });
    console.log(results);

    pg.end();
}

process.on('unhandledRejection', (err) => {
    console.error('An unhandled promise rejection occurred:', err);
    pg.end();
    process.exit(1);
});

main();
