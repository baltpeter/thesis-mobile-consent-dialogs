import glob from 'glob';
import fs from 'fs-extra';
import { db, pg } from './common/db.js';

(async () => {
    const successful_apps = (await db.many('select name from apps;')).map((r) => r.name);

    const fails = glob
        .sync('*.json', { cwd: '../data/failed-apps.tmp', absolute: true })
        .map((f) => fs.readFileSync(f, 'utf-8'))
        .map((j) => JSON.parse(j))
        .filter((f) => !successful_apps.includes(f.app_id))
        .reduce<Record<string, any>>((acc, cur) => ({ ...acc, [cur.app_id]: cur }), {});
    console.log('failed apps:', Object.keys(fails).length);

    const foreground_fails = Object.values(fails).filter((f: any) => f?.error?.message?.includes('foreground'));
    console.log('apps that quit immediately:', foreground_fails.length);

    const ios_os_version_fails = Object.values(fails).filter((f: any) =>
        f?.error?.stderr?.includes('The system version is lower than the minimum OS version specified for bundle')
    );
    console.log('iOS system version too low:', ios_os_version_fails.length);

    pg.end();
})();
