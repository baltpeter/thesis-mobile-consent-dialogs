import { join, basename } from 'path';
import fs from 'fs-extra';
import glob from 'glob';
// @ts-ignore
import dirname from 'es-dirname';
import pReduce from 'p-reduce';
import { z } from 'zod';
import { match } from 'ts-pattern';
import { base64Regex } from 'base64-search';
import { db } from './db.js';
import { data_argv } from './argv.js';
import type { Request } from './extract-request-data.js';

const argv = data_argv();
const data_dir = join(dirname(), '../../data');

export const platforms = ['android', 'ios'] as const;
export const dialog_types = ['dialog', 'maybe_dialog', 'notice', 'maybe_notice', 'link', 'neither'] as const;
const dialog_types_extended = [...dialog_types, ...['all_dialog', 'all_notice', 'any_privacy']] as const;
// prettier-ignore
export const violation_types = ['ambiguous_accept_button', 'accept_button_without_reject_button', 'ambiguous_reject_button', 'accept_larger_than_reject', 'accept_color_highlight', 'stops_after_reject'] as const;
const violation_types_extended = [...violation_types, 'any_violation'] as const;

export const indicators = {
    contacts: ['JGKfozntbF', 'TBFFZbBYea', '57543434', 'RYnlSPbEYh', 'q8phlLSJgq', 'N2AsWEMI5D', 'p0GdKDTbYV'],
    location: ['chreinerweg', 'raunschweig', '52.235', '10.564'],
    messages: ['9FBqD2CNIJ', '75734343'],
    clipboard: ['LDDsvPqQdT'],
    calendar: ['fWAs4GFbpN', 'urscf2178L'],
    reminders: ['b5jHg3Eh1k', 'HQBOdx4kx2'],
    notes: ['S0Ei7sFP9b'],
    health_data: ['DkwIXobsJN', 't5TfTlezmn', '1973-05-15'],
    apple_home_data: ['bEZf1h06j1', 'DX7BgPtH99', 'g1bVNue3On'],
    ssid: ['ALTPETER'],
    device_name: ['R2Gl5OLv20'],
    phone_number: ['85834346'],
    apple_id: ['vanessa.amsel@icloud.com'],
    os: ['Android 11', 'iOS 14.8'],
    model: ['sdk_gphone_x86_64_arm64', 'iPhone9,3'],

    serial_number: ['DNPV9C95HG7J', 'EMULATOR30X9X5X0'],
    mac_address: [
        // WiFi
        'D0:81:7A:6E:4C:6F',
        '02:15:b2:00:00:00',
        // Bluetooth
        'D0:81:7A:6E:4C:70',
        '3c:5a:b4:01:02:03',
    ],
    bssid: ['02:15:b2:00:01:00', '86:2a:a8:58:56:a8'],
    imei: ['356557088105639', '358240051111110'],
    idfa: ['00000000-0000-0000-0000-000000000000', 'ea70edc1-ac05-481c-8d2a-66b1be496a7e'],
    hashed_idfa: [
        '9f89c84a559f573636a47ff8daed0d33',
        'ab9930d1100c818f669304e60d39e4e7',
        'b602d594afd2b0b327e07a06f36ca6a7e42546d0',
        '401b7ec6420b220e2e18cf643027a5f853e0a77d',
        '12b9377cbe7e5c94e8a70d9d23929523d14afa954793130f8a3959c7b849aca8',
        'bcaa6dccfdd08085005c7bc6b92c1f56fd0069b57c5643c66e2a184aa3f48c4b',
        '70255c353a82bc55634a251d657f1813a74b3eca31dde11df99017f1de7504820fb054d1853b6e5f53251aaeb66d0469',
        'c6ce8fab0c476f96cd426dd99ed7b1f9a1a1342343e2b3193c28e5087b1dbf8b4483af733de56b76c53b0cdc6edefcd8',
        'a13dc074b31564a6a3cf4a605bff19fade6c19992a4123a7022d5a07c2e2d2d5e059ff0ba25ae0750d709fdb0ac757a1c615199a1c1422902d33c41e45b9f9d5',
        'fe62765267def303de48182576c4051ac661b210a2467e7c8ae2cd26b8de9e0e6abd0f6529a9b436c11b99b9495112a94c87c69bd9297151e4e38bb791fadec8',
    ],
    local_ips: [
        // Android
        '10.0.0.68',
        '10.0.2.18',
        '10.0.2.16',
        'fe80::c835:dcff:fe51:4104',
        'fe80::b826:2e05:6938:9257',
        'fec0::58d0:4c1e:1865:42a1',
        'fec0::8dd1:41b8:7408:6afc',
        'fe80::c88b:92ff:fef7:5bc5',
        'fec0::c88b:92ff:fef7:5bc5',
        'fec0::780e:8b16:a8d8:c083',

        // iOS
        '10.0.0.22',
        '10.0.0.16',
        'fe80::1080:5cb1:c586:6d1',
        '169.254.103.80',
        'fe80::4d0:8c8a:efe0:98f4',
        '2003:dd:af1a:dd00:18e6:d2c5:51fc:179c',
        '2003:dd:af1a:dd00:782c:457c:ad9d:491f',
        'fd31:4159::1010:3912:4d1c:8359',
        '2003:dd:af1a:dd00:4d0:8c8a:efe0:98f4',
        'fe80::cc7f:fff:fe21:eb95',
        'fe80::cc7f:fff:fe21:eb95',
        'fe80::e7e7:1705:13bd:e15b',
        'fe80::274f:7a93:5345:938a',
    ],
};

const wrap = (c: string) => `(${c})`;

export const dialogQuery = async (...conditions: (string | undefined)[]) => {
    const conds = conditions?.filter((c) => c) as string[];
    return +(
        await db.one(
            // prettier-ignore
            `select count(1) from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app${conds.length > 0 ? ` where ${conds.map(c => wrap(c)).join(' and ')}` : ''};`
        )
    ).count;
};

export const getDialogTypeCounts = (condition = '') =>
    pReduce(
        dialog_types_extended,
        async (acc, type) => ({
            ...acc,
            [type]: await dialogQuery(
                match(type)
                    .with('all_dialog', () => "verdict = 'dialog' or verdict = 'maybe_dialog'")
                    .with('all_notice', () => "verdict = 'notice' or verdict = 'maybe_notice'")
                    .with('any_privacy', () => "not verdict = 'neither'")
                    .otherwise(() => `verdict = '${type}'`),
                condition
            ),
        }),
        {} as Record<typeof dialog_types_extended[number], number>
    );

export const getViolationCounts = (condition = '') =>
    pReduce(
        violation_types_extended,
        async (acc, violation) => ({
            ...acc,
            [violation]: await dialogQuery(
                match(violation)
                    .with('any_violation', () =>
                        violation_types.map((v) => `cast(violations->>'${v}' as boolean)`).join(' or ')
                    )
                    .otherwise(() => `cast(violations->>'${violation}' as boolean)`),
                condition
            ),
        }),
        {} as Record<typeof violation_types_extended[number], number>
    );

export const getTopApps = () => {
    const normalizeCategory = (category: string) => {
        switch (category.replace(/\d+_|_app-ids/g, '').toUpperCase()) {
            case 'ALL':
            case 'ANDROID_WEAR':
            case 'AUTO_AND_VEHICLES':
            case 'BEAUTY':
            case 'CATALOGUES':
            case 'COMICS':
            case 'DATING':
            case 'DEVELOPER-TOOLS':
            case 'EVENTS':
            case 'FAMILY':
            case 'HOUSE_AND_HOME':
            case 'LIBRARIES_AND_DEMO':
            case 'PARENTING':
            case 'PERSONALIZATION':
            case 'STICKERS':
                return undefined;

            case 'ART_AND_DESIGN':
            case 'GRAPHICS-AND-DESIGN':
                return 'Graphics & Design';
            case 'BOOKS_AND_REFERENCE':
            case 'BOOKS':
            case 'REFERENCE':
                return 'Books & Reference';
            case 'BUSINESS':
                return 'Business';
            case 'COMMUNICATION':
            case 'SOCIAL':
            case 'SOCIAL-NETWORKING':
                return 'Social Networking';
            case 'EDUCATION':
                return 'Education';
            case 'ENTERTAINMENT':
                return 'Entertainment';
            case 'FINANCE':
                return 'Finance';
            case 'FOOD_AND_DRINK':
            case 'FOOD-AND-DRINK':
                return 'Food & Drink';
            case 'GAME':
            case 'GAMES':
                return 'Games';
            case 'HEALTH_AND_FITNESS':
            case 'HEALTH-AND-FITNESS':
                return 'Health & Fitness';
            case 'LIFESTYLE':
                return 'Lifestyle';
            case 'MAPS_AND_NAVIGATION':
            case 'NAVIGATION':
                return 'Maps & Navigation';
            case 'MEDICAL':
                return 'Medical';
            case 'MUSIC_AND_AUDIO':
            case 'MUSIC':
                return 'Music & Audio';
            case 'NEWS_AND_MAGAZINES':
            case 'MAGAZINES-AND-NEWSPAPERS':
            case 'NEWS':
                return 'News & Magazines';
            case 'PHOTOGRAPHY':
            case 'VIDEO_PLAYERS':
            case 'PHOTO-AND-VIDEO':
                return 'Photo & Video';
            case 'PRODUCTIVITY':
                return 'Productivity';
            case 'SHOPPING':
                return 'Shopping';
            case 'SPORTS':
                return 'Sports';
            case 'TOOLS':
            case 'UTILITIES':
                return 'Tools';
            case 'TRAVEL_AND_LOCAL':
            case 'TRAVEL':
                return 'Travel & Local';
            case 'WEATHER':
                return 'Weather';

            default:
                throw new Error(`Unknown category: ${category}.`);
        }
    };
    const top_apps_dir = (platform: 'android' | 'ios', date: string) =>
        join(dirname(), '../../data/top-apps', platform, 'top-lists', date);
    const _top_apps: Record<
        `${'android' | 'ios'}::${string}`,
        { id: string; platform: 'android' | 'ios'; best_position: number; categories: string[] }
    > = {};
    for (const platform of ['android', 'ios'] as const) {
        for (const category_data_path of glob.sync('*_app-ids.json', {
            cwd: top_apps_dir(platform, '2022-03-22'),
            absolute: true,
        })) {
            const category_data: string[] = JSON.parse(fs.readFileSync(category_data_path, 'utf-8'));
            for (const [index, id] of category_data.entries()) {
                const position = index + 1;

                let app_id: string;
                try {
                    app_id =
                        platform === 'android'
                            ? id
                            : JSON.parse(fs.readFileSync(join(argv.privacy_labels_dir, `${id}.json`), 'utf-8')).data[0]
                                  .attributes.platformAttributes.ios.bundleId;
                } catch {
                    continue;
                }

                const key = `${platform}::${app_id}` as const;
                const category = normalizeCategory(basename(category_data_path, '.json'));

                if (_top_apps[key]) {
                    if (position < _top_apps[key].best_position) _top_apps[key].best_position = position;
                    if (category && !_top_apps[key].categories.includes(category))
                        _top_apps[key].categories.push(category);
                } else
                    _top_apps[key] = {
                        id: app_id,
                        platform,
                        categories: category ? [category] : [],
                        best_position: position,
                    };
            }
        }
    }
    return _top_apps;
};

export const requestHasIndicator = (r: Request, indicators: string[]) => {
    const plain_indicators = indicators.map((i) => i.toLowerCase());
    const base64_indicators = plain_indicators.map((i) => new RegExp(base64Regex(i), 'i'));
    for (const property of ['content', 'content_raw', 'path'] as const) {
        if (indicators.some((i) => r[property]?.toString().toLowerCase().includes(i))) return true;
        if (base64_indicators.some((i) => i.test(r[property]?.toString() || ''))) return true;
    }
    return false;
};
export const hasPseudonymousData = (data_types: Set<string> | string[]) =>
    ['idfa', 'idfv', 'hashed_idfa', 'other_uuids', 'public_ip'].some((type) =>
        Array.isArray(data_types) ? data_types.includes(type) : data_types.has(type)
    );

const data_catgories_schema = z.array(
    z
        .object({
            dataCategory: z.string(),
            identifier: z.string(),
            dataTypes: z.array(z.string()),
        })
        .strict()
);
export const privacy_types_schema = z.array(
    z
        .object({
            privacyType: z.string(),
            identifier: z.enum([
                'DATA_NOT_COLLECTED',
                'DATA_USED_TO_TRACK_YOU',
                'DATA_LINKED_TO_YOU',
                'DATA_NOT_LINKED_TO_YOU',
            ]),
            description: z.string(),
            dataCategories: data_catgories_schema,
            purposes: z.array(
                z
                    .object({
                        purpose: z.string(),
                        identifier: z.string(),
                        dataCategories: data_catgories_schema,
                    })
                    .strict()
            ),
        })
        .strict()
);
// Maps from Apple's privacy label "types of data" (https://developer.apple.com/app-store/app-privacy-details/) to our
// data types.
export const privacy_label_data_type_mapping = {
    'Email Address': ['apple_id'],
    'Phone Number': ['phone_number'],
    Health: ['health_data'],
    Location: ['lat', 'long', 'location'],
    Contacts: ['contacts'],
    'Emails or Text Messages': ['messages'],
    'Other User Content': ['clipboard', 'reminders', 'calendar', 'notes', 'apple_home_data'],
    'Product Interaction': ['viewed_page', 'in_foreground'],
    'Performance Data': ['ram_total', 'ram_free', 'disk_total', 'disk_free', 'uptime'],
    'Device ID': ['idfa', 'idfv', 'hashed_idfa'],
    'Other Diagnostic Data': [
        'rooted',
        'emulator',
        'network_connection_type',
        'signal_strength_cellular',
        'signal_strength_wifi',
        'is_charging',
        'battery_percentage',
        'accelerometer_x',
        'accelerometer_y',
        'accelerometer_z',
        'rotation_x',
        'rotation_y',
        'rotation_z',
    ],
    'Other Data Types': ['device_name', 'carrier', 'roaming', 'mac_address', 'bssid', 'local_ips', 'volume'],
};

export const getFilterList = (list: 'easylist' | 'easyprivacy') =>
    fs
        .readFile(join(data_dir, 'upstream', `${list}.txt`), 'utf-8')
        .then((f) => f.split('\n').filter((l) => !l.startsWith('#')));

const uuid_regex = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
// Ignored: locale, uuid, uid, cid, uuid2, pid, pxrc, CMRUM3
export const cookie_regexes = {
    // AHWqTUmFvw__WeRDSraQp2NhCalU41eikkyUfIOEMxI7Vp0p0sdcLDIv8EMNduxt
    // AHWqTUlgfB7wedtxoSrNgRqeZ31wPsZiS99c7xMN_XzTxtQMWlvw_rvikbcbQMQF214
    IDE: /^([A-Za-z0-9_-]{64}|[A-Za-z0-9_-]{67})$/,

    // GA1.1.1044166033.1650905135
    // GA1.2.1892128189.1648899285
    // GA1.1.123924100.1650905000
    // GA1.2.431873635.1649584464
    // GA1.2.14aaf149-0c05-4ea7-8dcb-6f3ab5ac9af4
    _ga: /^GA1\.(1|2)\.(\d{9,10}\.\d{10}|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})$/,

    // GA1.2.2125670171.1649340080
    // GA1.2.380813265.1648923339
    _gid: /^GA1\.2\.\d{9,10}\.\d{10}$/,

    // 511=vVNkk3lJFeyIIRpT-pJvrUlZ9j_fUhW3Mp_oKnHE7Bw5GGSiRunnUdhOp5qf4ajdEMXsw1EkzlHQjwJA88l11flFMmA2NySQrqVn4iYn9HP_3qbceuidEz5q8yAO1ymNKFQUylWYbeXCX2N_S6ajGx1OAzzp3oKMrj7ewH8ZxPk
    // 511=EY3gnUzXNdG6Zj1FPtWLO5p9-MAYnao7ndvgKRmmiqvvGymFs6P39HSDuq-mk7f7camJ0zFlK38J0ef1k-fj-qHXzslYje0B6l__4sDltCet-GjZox99_BiTPwFd7RAHEIeNjdT-AKiDLKN2VCE1eIg7X4n218FAOruli64IYEA
    NID: /^511=[A-Za-z0-9_-]{171}$/,

    // fb.0.1648593215708.483913480
    // fb.0.1649351528615.1751747275
    // fb.1.1649249967885.487756718
    // fb.1.1649231165901.1946893986
    _fbp: /^fb\.(0|1)\.\d{13}\.\d{9,10}$/,

    // 20144213787487035316227840375497882459
    // 21905346236469297217484294380831727438
    // 25270196951928601723369969275854194336
    demdex: /^\d{38}$/,

    // 1.1.2142681364.1649278161
    // 1.1.361264100.1650855090
    _gcl_au: /^1\.1\.\d{9,10}\.\d{10}$/,

    // 454da3cc-9ac6-4723-b5ce-ecd8b800dd4e
    // 5a108622-ed5b-41c9-ac21-92e54883d3cb
    sp: uuid_regex,

    // d=ABIBBOiXQWICEMvEvqs-vks7P395Wb5RElc
    // d=AQIBBNrVRGICEIIv8N3FCD7dQbXXE6KLSxcFEgABBgDjRGJGYuA9b2UBACAAAAYsQVFBQkJnQmlST05pUmxhVXFRZjgmcz1BUUFBQUpxUmtZMm8mZz1Za1RWNlE&S=AQAAAhUQV2SkFTKH3Miew_mRK2I
    A3: /^d=(([A-Za-z0-9_-]{123}&S=[A-Za-z0-9_-]{27})|[A-Za-z0-9_-]{35})$/,

    // 5MWshy95gnI
    // BPzNEm7H87c
    VISITOR_INFO1_LIVE: /^[A-Za-z0-9_-]{11}$/,

    // 1
    _gat: /^\d+$/,

    // 2744a80f-f392-47ff-855c-2eff65dd263f
    // 86d19652-83c9-4ee6-b9f7-fd11d0b0ef28
    __scid: uuid_regex,

    // 0a0886c1-a9f3-461b-a097-98004f13d18d
    // 18b7e46f-3249-42e8-a2ea-7ede605a1dc2
    ajs_anonymous_id: uuid_regex,

    // 39539352017897559004135855554440358653
    // 72072443767493302251417414226993333656
    aam_uuid: /^\d{38}$/,

    // true
    s_cc: /^true|false$/,

    // [CS]v1|31259867B996551A-6000054F29364FD0[CE]
    // [CS]v1|3132FD7994855084-60000E05D9FABC8C[CE]
    s_vi: /^\[CS]v1\|[0-9A-F]{16}-[0-9A-F]{16}\[CE]$/,

    // lX+JpZkm9FAd6HMZavWAbmjR2IPfg3WYzgFHrcyR2bVvYrEKqzEqbuH1fY5r+PMmWI7QzMzpvN+J5tIYxlXX3HlEuts=
    // Ne2QUSP2T1W1mFjhoUb1wqUy4K4YHh5rBJOiPR/7gajvV9kiHXVjjn85Cax/Q+ZkVtX8tH7HJh7sNG5wbtvZKH8Ol7w=
    i: /^[A-Za-z0-9+/]{91}=$/,

    // 43bd9d10c4c111eca241411e2351186a
    // 627af290b5a911ecb757732605cff123
    _uetsid: /^[a-f0-9]{32}$/,

    // 43bdf6e0c4c111ecbd25eb4a21d4a107
    // 627afc40b5a911ec88db893e269636b8
    _uetvid: /^[a-f0-9]{32}$/,

    // 5187
    // 5191
    CMPS: /^\d{4}$/,

    // b723afac-6fea-4bdd-a61b-f66884193d1e
    // c952811c-fce3-525d-895d-0bc8eb15da1e
    tuuid: uuid_regex,

    // 1649231167
    // 1649231168
    tuuid_lu: /^\d{10}$/,

    // 03F99123130C6C4A332D80B312DE6DB4
    // 1F00A68C6B166B3C22B2B7F26A7D6A58
    MUID: /^[0-9A-F]{32}$/,

    // GUID=9fa8cc28fe274d199fbc668c613e9728
    // GUID=fc24242544124f208ff15ddb8e02cf56
    MC1: /^GUID=[a-f0-9]{32}$/,

    // 34373079556147294712325758697589361813
    // 39539352017897559004135855554440358653
    dpm: /^\d{38}$/,

    // Yk1FP2JNRT8A
    // YkjR2GJI0dgA
    CMST: /^[A-Za-z0-9]{12}$/,

    // a9413911-3e12-41af-aefa-ec5a13dcad0d
    // ce648074-fa8a-4503-aaab-03f10ff3914a
    BCSessionID: uuid_regex,

    // ID=554d7edead3ca147:T=1650850692:S=ALNI_MbPlymzIiYQ2wj62AdGI1Y6MjtXqQ
    // ID=5ea395d114cb397b:T=1650864736:S=ALNI_MYu7TdN46YN14OAiv_VTmtTeEUyDg
    __gads: /^ID=[0-9a-f]{16}:T=\d{10}:S=[0-9A-Za-z_]{34}$/,

    // g_surferid~Yk1FQQAGX7zHaQA-
    // g_surferid~YmYyYAAAAI3gSAP0
    everest_g_v2: /^g_surferid~[0-9A-Za-z-]{16}$/,

    // session#02f92aec3c4e4ef5ba8643af8d595e20#1650852405
    // session#02f92aec3c4e4ef5ba8643af8d595e20#1650852405|PC#02f92aec3c4e4ef5ba8643af8d595e20.37_0#1650852348
    mbox: /^session#[0-9a-f]{32}#\d{10}(\|PC#[0-9a-f]{32}\.\d{2}_\d#\d{10})?$/,

    // 3NRGhDiFx42f7bZibIGghuW5lskVG0XbykTb1M20et0=
    // Zjm8Fbur0L0Te6nOOEU68i1j1B4ktgblPhh77UxK5jE=
    rlas3: /^[A-Za-z0-9+]{43}=$/,

    // Yk1FP2MKpmaD726iy7KYewAA
    // YkjR2BvNGy60bdsr1ibkmwAA
    CMID: /^[A-Za-z0-9]{24}$/,

    // 1132
    // 1146
    CMPRO: /^\d{4}$/,
};
