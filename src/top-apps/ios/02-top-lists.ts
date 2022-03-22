import { join } from 'path';
import fetch from 'node-fetch';
import fs from 'fs-extra';
import slugify from '@sindresorhus/slugify';
// @ts-ignore
import dirname from 'es-dirname';
import { apple_store_front, apple_ios_pop_ids } from '../../common/consts.js';
import { pause } from '../../common/util.js';

const date = new Date().toISOString().substring(0, 10);

const api_url = (genre_id: string) =>
    `https://itunes.apple.com/WebObjects/MZStore.woa/wa/viewTop?genreId=${genre_id}&popId=${apple_ios_pop_ids.top_free_iphone}`;
const out_dir = join(dirname(), '..', '..', '..', 'data', 'top-apps', 'ios', 'top-lists', date);

(async () => {
    await fs.ensureDir(out_dir);

    const genres: Record<string, string> = JSON.parse(
        (await fs.readFile(join(dirname(), '../../../data/top-apps/ios/genres/', `genres_${date}.json`))).toString()
    );

    for (const [genre_id, genre_name] of Object.entries(genres)) {
        const json = await fetch(api_url(genre_id), { headers: { 'X-Apple-Store-Front': apple_store_front } }).then(
            (r) => r.json() as unknown as Record<string, any>
        );
        await fs.writeFile(join(out_dir, `${genre_id}_${slugify(genre_name)}_raw.json`), JSON.stringify(json, null, 4));

        const app_ids = json?.pageData?.segmentedControl?.segments?.[0]?.pageData?.selectedChart?.adamIds;
        await fs.writeFile(
            join(out_dir, `${genre_id}_${slugify(genre_name)}_app-ids.json`),
            JSON.stringify(app_ids || [], null, 4)
        );

        await pause(1000 + Math.random() * 500);
    }
})();
