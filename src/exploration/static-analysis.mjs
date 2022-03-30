import { join } from 'path';
import glob from 'glob';
import { execa } from 'execa';

const for_android = false;

const apps_dir = for_android ? '/media/benni/storage2/tmp/apks' : '/media/benni/storage2/tmp/3u';

(async () => {
    const app_ids = glob.sync(for_android ? '*' : '*.ipa', { absolute: false, cwd: apps_dir });

    let total = 0;
    let with_iabtcf = 0;
    let with_certified_cmp = 0;
    for (const app_id of app_ids) {
        try {
            const app_file = for_android ? join(apps_dir, app_id, `${app_id}.apk`) : join(apps_dir, app_id);

            let lines;
            if (for_android) {
                const { stdout } = await execa('dexdump', [app_file], { stdout: 'pipe', reject: false });
                lines = stdout.split('\n').filter((l) => l.includes('Class descriptor'));
            } else {
                const { stdout } = await execa('zipinfo', ['-1', app_file], { stdout: 'pipe', reject: false });
                lines = stdout.split('\n').filter((l) => l.match(/^Payload\/.+\.app\/Frameworks\/.+\.framework\//));
            }

            total++;
            if (lines.filter((l) => l.match(/iabtcf/i)).length > 0) with_iabtcf++;
            if (
                lines.filter((l) =>
                    // List based on:
                    //   * https://iabeurope.eu/cmp-list/,
                    //   * https://www.blog.udonis.co/mobile-marketing/mobile-games/consent-management-tools,
                    //   * https://instabug.com/blog/top-mobile-app-consent-management-tools/
                    l.match(
                        /appconsent|axeptio|bedrock|clarip|commandersact|consentdesk|consentmanager|cookiepro|didomi|easybrain|freecmp|fundingchoices|iubenda|madvertise|next14|ogury|onetrust|osano|sfbx|sibboventures|sourcepoint|tamoco|trustarc|txgroup|uniconsent|usercentrics/i
                    )
                ).length > 0
            )
                with_certified_cmp++;

            console.log(
                app_id,
                '::',
                'with iabtcf:',
                with_iabtcf,
                'with any CMP:',
                with_certified_cmp,
                'total:',
                total
            );
        } catch (err) {
            console.error(err);
        }
    }
})();
