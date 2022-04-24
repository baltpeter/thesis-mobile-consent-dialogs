import { join, basename } from 'path';
import fs from 'fs-extra';
import glob from 'glob';
// @ts-ignore
import dirname from 'es-dirname';
import pReduce from 'p-reduce';
import { match } from 'ts-pattern';
import { base64Regex } from 'base64-search';
import { db } from './db.js';
import { data_argv } from './argv.js';
import type { Request } from './extract-request-data.js';

const argv = data_argv();

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
