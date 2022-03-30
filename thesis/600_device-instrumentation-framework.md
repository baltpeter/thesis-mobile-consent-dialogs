# Device Instrumentation Framework

* Based on previous work by author, unified framework for Android and iOS, more robust, added Appium stuff and interaction.

## Platforms

* Emulator for Android
    * Use Android 11 x86_64 (best compatibility with apps from experience)
* Real device for iOS
* Device preparation (see Appendix for full steps)
    * iOS
        * Jailbreak
        * SSH server
        * Settings
        * Cydia packages:
            * [Activator](https://cydia.saurik.com/package/libactivator/)
            * [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2)
            * [Frida](https://frida.re/docs/ios/#with-jailbreak)
        * Setup mitmproxy as… proxy
    * Android
        * Uninstall unnecessary Google apps to avoid their background traffic.
        * Disable captive portal checks to further reduce background noise.
        * Install mitmproxy certificate as root CA.
        * Install Frida.
* Honey data
    * Randomly generated values with sufficient entropy to make sure they can't appear in traffic by chance.
    * Some devices identifiers read
    * Table with (type, read/set, platform)

## Device Instrumentation

* XCUITest (iOS) and UiAutomator2 (Android)
* Appium as common interface over the two
    * Setup problems on iOS
        * Docs mentioned that Appium doesn't work with jailbroken device, wrong, corrected: https://github.com/appium/appium/issues/16211
        * Had to use manual configuration (https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/#full-manual-configuration) and additionally pass `-allowProvisioningUpdates` to `xcodebuild`. (Corrected in docs: https://github.com/appium/appium/issues/16212, https://github.com/appium/appium/pull/16215)
        * Full steps in Appendix?
* Custom platform-specific interfaces
    * Frida
        * On M1 Mac: Manual compilation of Node bindings necessary, full steps in Appendix?

## Traffic Collection

* mitmproxy
* Certification pinning bypasses
* Background noise filtering

## Dataset of Apps

### App Selection

* To get a sufficient amount of apps, on both platforms we cannot just rely on the overall top charts as they don't contain enough apps. Instead, we rely on the top charts per category and merge the results.

TODO: List available categories per platform?

#### Android

* Google doesn't offer an API for the top apps from the Play Store
* The Play Store web UI does have top lists for apps and games though (https://play.google.com/store/apps/top), distinguishing between “top for 0€”, “top selling”, and “top grossing“, with 200 apps each. This would yield at most 400 free apps though (assuming the top free lists for apps and games are disjunct), which is not sufficient for this thesis.
* External services do sell top chart APIs for the Play Store, but they don't disclose how they are compiled and it's better to rely on the official source.
* Going through the linked category pages (e.g. https://play.google.com/store/apps/category/TOOLS) offers various sublists on different topics, but those aren't top charts and the number of apps in them varies wildly between a handful and up to around 50.
* Google does however publish top charts per category, once again with 200 apps each. Not linked anywhere as far as the author can tell, but can be found through search engines. Explain link: `https://play.google.com/store/apps/top/category/<category_id>?gl=DE`. From there, have to click on “top for 0€” link (which contains obfuscated parameters and can't be guessed).
* Category IDs can be determined from the links in the category dropdown at the top of the web page. Those look like: `https://play.google.com/store/apps/category/TOOLS`, where `TOOLS` is the category ID.
* From that, we can write a scraper that extracts the top free apps per category.  Uses Playwright browser automation framework by Microsoft. Iterates over category IDs, visits page for each, clicks link, continues scrolling to the bottom of the page until it doesn't get larger anymore (to defeat infinite scrolling, results are loaded dynamically using JS) and then extracts ID, name and top list position for each app on the page.
* Done on 2022-03-22:
    * With all found apps: Apps before deduplication: 6970, Apps after deduplication: 6817
    * Top 100 per category: Apps before deduplication: 3500, Apps after deduplication: 3421

#### iOS

* Apple offers an [RSS feed generator](https://rss.applemarketingtools.com/) for the top charts of various media types they sell (including apps). Using that, it is possible to obtain an XML or JSON file (despite the tool's name) of the top free or top paid apps per country on the App Store. The generator only returns up to 50 apps, but it is possible to retrieve up to 200 apps by manually adjusting the result limit parameter in the URL: `https://rss.applemarketingtools.com/api/v2/de/apps/top-free/200/apps.json`. Requesting more than 200 apps will result in an internal server error.
* It used to be possible to get up to 1,200 top apps through `https://itunes.apple.com/WebObjects/MZStore.woa/wa/topChartFragmentData` endpoint that was used in old version of the iOS App Store [@johnsonAppStoreHow2015]. However, that endpoint now only provides the top 100 apps.
* iTunes on Windows^[Newer versions of iTunes don't include support for the iOS App Store anymore, but Apple offers a special, unsupported but continuing to work as of the time of writing, version of iTunes (12.6.5.3) that still contains this feature and doesn't prompt the user to update to newer versions: <https://support.apple.com/HT208079>] can however display top charts for each category (called “genre” by Apple), with up to 200 results each. Observing the iTunes' network traffic when loading these pages revealed the following endpoint: `https://itunes.apple.com/WebObjects/MZStore.woa/wa/viewTop?cc=de&genreId=36&l=en&popId=27`
* The `cc` and `l` GET parameters control the country and language respectively.
* The `popId` parameter determines the type of top chart returned, with the following possible values (again determined by observing the iTunes network traffic): `27` (top free apps for iPhone), `30` (top paid apps for iPhone), `38` (top grossing apps for iPhone), `44` (top free apps for iPad), `46` (top grossing apps for iPad), `47` (top paid apps for iPad).
* Finally, the `genreId` parameter controls the category the returned top list is for. A list of all possible categories on iTunes can be retrieved from the `https://itunes.apple.com/WebObjects/MZStoreServices.woa/ws/genres` endpoint [@appleinc.GenreIDsAppendix2019]. `36` is the first-level category for all apps on the App Store. The second-level then has the actual app categories, e.g. `6000` for “Business”. There are also third-level categories but only for “Games” and “Newsstand”, so they are excluded here.
* In addition to the GET parameters, the `X-Apple-Store-Front` header also needs to be set. It consists of between one and three numbers and has the following format: `<country>-<language>,<platform>` (only `<country>` is required, the others can be left off). Setting `<country>` to `143443` means Germany for example; a list of possible countries used to be available in the iTunes affiliate partner documentation and can still be accessed through the Internet Archive [@appleinc.AdvancedPartnerLinking2019]. Among the available values for `<language>` are `1` (US English), `2` (British English), `3` (French), and `4` (German) [@olbaumHowITunesSelects2006; @IosWhatDoes2019]. It is not possible to combine country and language arbitrarily, for example setting US English as the language but German as the country does not work, where as British English does work for Germany. Finally, the `<platform>` values determines the Apple application the request is (supposedly) coming from, with `28` meaning iTunes 12 for example [@zhoufykScrapeRatingsITunes2019].
* TODO: Importantly: JSON instead of html
* TODO: but for some reason `json.storePlatformData.lockup.results` only has 84 results with meta data
* TODO: to access all IDs: `json.pageData.segmentedControl.segments[0].pageData.selectedChart.adamIds`
* Done on 2022-03-22:
    * With all found apps: Apps before deduplication: 5205, Apps after deduplication: 4968
    * Top 100 per category: Apps before deduplication: 2605, Apps after deduplication: 2486

### App Acquisition

---

TODO:

* On iOS, if apps signed for Apple ID other than the one signed in on iPhone are installed, "To open “<app>”, sign in with the Apple ID that purchased it." is displayed. If one signs in with the other Apple ID there, running apps from both Apple IDs is then possible (but second Apple ID doesn't seem to be displayed anywhere in the UI).
