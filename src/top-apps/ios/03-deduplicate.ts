import { join } from 'path';
import glob from 'glob';
import fs from 'fs-extra';
import slugify from '@sindresorhus/slugify';
// @ts-ignore
import dirname from 'es-dirname';
import { apple_store_front, apple_ios_pop_ids } from '../../common/consts.js';
import { pause } from '../../common/util.js';

const date = new Date().toISOString().substring(0, 10);
const out_dir = join(dirname(), '..', '..', '..', 'data', 'top-apps', 'ios', 'top-lists', date);

(async () => {
    await fs.ensureDir(out_dir);

    const app_ids = glob
        .sync('*_app-ids.json', { cwd: out_dir, absolute: true })
        // TODO: We can get up to 200 per genre.
        .map((p) => JSON.parse(fs.readFileSync(p, 'utf-8')).slice(0, 100))
        .flat();
    const deduplicated_app_ids = [...new Set(app_ids)];
    await fs.writeFile(join(out_dir, 'app_ids.json'), deduplicated_app_ids.join('\n'));
    console.log('Apps before deduplication:', app_ids.length);
    console.log('Apps after deduplication:', deduplicated_app_ids.length);
})();
