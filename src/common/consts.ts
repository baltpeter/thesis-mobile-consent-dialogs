// The format is: `<country>-<language>,<platform>`, where:
//     * `143443` is Germany (https://web.archive.org/web/20191206001952/https://affiliate.itunes.apple.com/resources/documentation/linking-to-the-itunes-music-store/#appendix)
//     * `-2` is English (`-4` or leaving the parameter off would be German)
//     * `29` is "P84" (no idea what that is) but importantly returns JSON (https://gist.github.com/sgmurphy/1878352?permalink_comment_id=2977743#gistcomment-2977743)
export const apple_store_front = '143443-2,29';
export const apple_ios_apps_genre_id = 36;
export const apple_ios_pop_ids = {
    top_free_iphone: 27,
    top_paid_iphone: 30,
    top_grossing_iphone: 38,
    top_free_ipad: 44,
    top_grossing_ipad: 46,
    top_paid_ipad: 47,
};
