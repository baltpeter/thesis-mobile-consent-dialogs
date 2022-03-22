import { join } from 'path';
import fs from 'fs-extra';
import { firefox } from 'playwright';
// @ts-ignore
import dirname from 'es-dirname';
import { pause } from '../../common/util.js';

const date = new Date().toISOString().substring(0, 10);

const category_url = (category_id: string) => `https://play.google.com/store/apps/top/category/${category_id}?gl=DE`;
const out_dir = join(dirname(), '..', '..', '..', 'data', 'top-apps', 'android', 'top-lists', date);

// To generate, run the following in the browser console after selecting the `ul` for the categories dropdown on
// https://play.google.com/store/apps:
// Array.from(document.querySelector('#action-dropdown-children-Categories .TEOqAc').querySelectorAll('a')).reduce((acc, cur) => ({...acc, [cur.href.match(/\/([^\/]+?)$/)[1]]: cur.innerText}), {})
// Manually add the Games and Kids categories as we don't want their subcategories.
const categories = {
    ART_AND_DESIGN: 'Art & Design',
    AUTO_AND_VEHICLES: 'Auto & Vehicles',
    BEAUTY: 'Beauty',
    BOOKS_AND_REFERENCE: 'Books & Reference',
    BUSINESS: 'Business',
    COMICS: 'Comics',
    COMMUNICATION: 'Communication',
    DATING: 'Dating',
    EDUCATION: 'Education',
    ENTERTAINMENT: 'Entertainment',
    EVENTS: 'Events',
    FINANCE: 'Finance',
    FOOD_AND_DRINK: 'Food & Drink',
    HEALTH_AND_FITNESS: 'Health & Fitness',
    HOUSE_AND_HOME: 'House & Home',
    LIBRARIES_AND_DEMO: 'Libraries & Demo',
    LIFESTYLE: 'Lifestyle',
    MAPS_AND_NAVIGATION: 'Maps & Navigation',
    MEDICAL: 'Medical',
    MUSIC_AND_AUDIO: 'Music & Audio',
    NEWS_AND_MAGAZINES: 'News & Magazines',
    PARENTING: 'Parenting',
    PERSONALIZATION: 'Personalization',
    PHOTOGRAPHY: 'Photography',
    PRODUCTIVITY: 'Productivity',
    SHOPPING: 'Shopping',
    SOCIAL: 'Social',
    SPORTS: 'Sports',
    TOOLS: 'Tools',
    TRAVEL_AND_LOCAL: 'Travel & Local',
    VIDEO_PLAYERS: 'Video Players & Editors',
    ANDROID_WEAR: 'Watch apps',
    WEATHER: 'Weather',
    GAME: 'Games',
    FAMILY: 'Kids',
};

const scroll_to_bottom = () =>
    new Promise<void>((res) => {
        const interval = setInterval(async function () {
            // @ts-ignore
            const old_height = document.body.scrollHeight;
            // @ts-ignore
            window.scrollBy(0, document.body.clientHeight);
            await new Promise((res2) => setTimeout(res2, 5000));
            // @ts-ignore
            const new_height = document.body.scrollHeight;
            if (new_height <= old_height) {
                clearInterval(interval);
                res();
            }
        }, 10);
    });
const get_apps = () =>
    // @ts-ignore
    Array.from(document.querySelectorAll('a[href^="/store/apps/details?id="] div'))
        // Only consider visible elements, see: https://stackoverflow.com/a/21696585
        // @ts-ignore
        .filter((e) => e.offsetParent)
        .map((e, i) => ({
            // @ts-ignore
            app_id: e.parentElement.href.replace('https://play.google.com/store/apps/details?id=', ''),
            // @ts-ignore
            app_name: e.innerText,
            position: i + 1,
        }));

(async () => {
    await fs.ensureDir(out_dir);

    const browser = await firefox.launch({ headless: false });
    const page = await browser.newPage();

    for (const [category_id] of Object.entries(categories)) {
        try {
            await page.goto(category_url(category_id));
            await page.locator('text=Top for €0').click();

            await page.evaluate(scroll_to_bottom);
            const apps = await page.evaluate(get_apps);

            await fs.writeFile(join(out_dir, `${category_id}_raw.json`), JSON.stringify(apps, null, 4));
            await fs.writeFile(
                join(out_dir, `${category_id}_app-ids.json`),
                JSON.stringify(
                    apps.map((a) => a.app_id),
                    null,
                    4
                )
            );

            await pause(2000 + Math.random() * 500);
        } catch (err) {
            console.error(`Failed to get top apps for category "${category_id}":`, err);
        }
    }

    await browser.close();
})();
