import { join } from 'path';
import fetch from 'node-fetch';
import fs from 'fs-extra';
// @ts-ignore
import dirname from 'es-dirname';
import { apple_store_front, apple_ios_apps_genre_id } from '../../common/consts.js';

const date = new Date().toISOString().substring(0, 10);

const api_url = 'https://itunes.apple.com/WebObjects/MZStoreServices.woa/ws/genres';
const out_dir = join(dirname(), '..', '..', '..', 'data', 'top-apps', 'ios', 'genres');

(async () => {
    await fs.ensureDir(out_dir);

    const genre_json = await fetch(api_url, { headers: { 'X-Apple-Store-Front': apple_store_front } }).then(
        (r) => r.json() as unknown as Record<number, any>
    );
    await fs.writeFile(join(out_dir, `genres_raw_${date}.json`), JSON.stringify(genre_json, null, 4));

    const apps_genres = genre_json[apple_ios_apps_genre_id];
    if (apps_genres.name !== 'App Store') throw new Error('Unexpected API response.');

    const subgenres = (Object.values(apps_genres.subgenres) as { name: string; id: string }[]).reduce<
        Record<string, string>
    >((acc, cur) => ({ ...acc, [cur.id]: cur.name }), {});
    subgenres[36] = 'all';
    console.log(subgenres);
    await fs.writeFile(join(out_dir, `genres_${date}.json`), JSON.stringify(subgenres, null, 4));
})();
