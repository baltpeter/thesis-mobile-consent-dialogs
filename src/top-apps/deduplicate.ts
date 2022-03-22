import { join } from 'path';
import glob from 'glob';
import fs from 'fs-extra';
// @ts-ignore
import dirname from 'es-dirname';

const date = new Date().toISOString().substring(0, 10);
const out_dir = (platform: 'android' | 'ios') =>
    join(dirname(), '..', '..', 'data', 'top-apps', platform, 'top-lists', date);

(async () => {
    for (const platform of ['android', 'ios'] as const) {
        const dir = out_dir(platform);
        await fs.ensureDir(dir);

        const app_ids = glob
            .sync('*_app-ids.json', { cwd: dir, absolute: true })
            // TODO: We can get more apps if needed.
            .map((p) => JSON.parse(fs.readFileSync(p, 'utf-8')).slice(0, 100))
            .flat();
        const deduplicated_app_ids = [...new Set(app_ids)];
        await fs.writeFile(join(dir, 'app_ids.json'), deduplicated_app_ids.join('\n'));
        console.log(`On ${platform === 'android' ? 'Android' : 'iOS'}:`);
        console.log(
            'Apps before deduplication:',
            app_ids.length,
            '::',
            'Apps after deduplication:',
            deduplicated_app_ids.length
        );
        console.log();
    }
})();
