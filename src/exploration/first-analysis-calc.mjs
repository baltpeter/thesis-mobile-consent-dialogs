import { join, basename } from 'path';
import glob from 'glob';
import fs from 'fs-extra';

const res_dir = '../../data.tmp';

(async () => {
    const prefs = glob
        .sync(`*`, { absolute: true, cwd: res_dir })
        .map((p) => ({ path: join(p, 'prefs.json'), app_id: basename(p) }))
        .filter((a) => fs.existsSync(a.path))
        .map((a) => ({ ...a, prefs: JSON.parse(fs.readFileSync(a.path, 'utf-8')) }));
    console.log('Apps with readable prefs:', prefs.length);

    const non_empty_prefs = prefs.filter((a) => Object.keys(a.prefs).length > 0);
    console.log('Apps with non-empty prefs:', non_empty_prefs.length);

    const privacy_prefs = non_empty_prefs.filter((a) =>
        Object.keys(a.prefs).some((k) => k.match(/gdpr|iabtcf|didomi|IABUSPrivacy_String/i))
    );
    console.log('Apps with privacy-related prefs:', privacy_prefs.length);
    console.log(privacy_prefs.map((a) => [a.app_id, Object.keys(a.prefs)]));
})();
