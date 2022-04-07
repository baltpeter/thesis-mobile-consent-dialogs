# Device Instrumentation Framework

We developed a framework for automated instrumentation of Android and iOS apps for this analysis. The framework can manage (install, run, and uninstall) apps, manage app permissions and extract app preferences, collect the device network traffic (including HTTPS and certificate pinned traffic) while an app is running, as well as analyse and interact with elements displayed on screen. It builds on and extends previous work on data protection in mobile apps that the author was involved in (TODO: cite).

## Device Preparation

* Emulator for Android
    * Use Android 11 x86_64 (best compatibility with apps from experience)
* Real device for iOS
    * iOS Simulator cannot run IPA apps packaged for distribution as downloaded from the App Store but only development builds. Without source code access, we cannot produce those.
    * Commercial providers like Appetize.io and RunThatApp only resell iOS Simulator [@appetize.iollcUploadingApps2022; @runthatapp.cominc.RunThatAppFileSubmission2021].

(see Appendix for full steps)

### Android

* Uninstall unnecessary Google apps to avoid their background traffic.
* Disable captive portal checks to further reduce background noise. [@yanAnswerCaptivePortal2017]
* Install mitmproxy certificate as root CA. [@joseAnswerAdbRemount2020; @ropnopConfiguringBurpSuite2018; @0x10f2cInterceptingTrafficAndroid2019]
* Install Frida.

### iOS

* Jailbreak
* SSH server
* Settings
* Cydia packages:
    * [Activator](https://cydia.saurik.com/package/libactivator/)
    * [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2)
    * [Frida](https://frida.re/docs/ios/#with-jailbreak)
* Setup mitmproxy as… proxy

### Honey Data

* Randomly generated values with sufficient entropy to make sure they can't appear in traffic by chance.
* Some devices identifiers read
* Table with (type, read/set, platform)

## Device Instrumentation

* Custom platform-specific interfaces (TODO: Maybe as table?)
    * install, run, uninstall apps
        * Android: install-multiple
    * grant/deny permissions
        * Android
            * -g
            * dangerous [@latifAnswerListADB2020]
    * extract app preferences
    * Frida
        * On M1 Mac: Manual compilation of Node bindings necessary, full steps in Appendix?

* XCUITest (iOS) and UiAutomator2 (Android)
* Appium as common interface over the two
    * Setup problems on iOS
        * Docs mentioned that Appium doesn't work with jailbroken device, wrong, corrected: https://github.com/appium/appium/issues/16211
        * Had to use manual configuration (https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/#full-manual-configuration) and additionally pass `-allowProvisioningUpdates` to `xcodebuild`. (Corrected in docs: https://github.com/appium/appium/issues/16212, https://github.com/appium/appium/pull/16215)
        * Full steps in Appendix?
    * Further, on iOS we noticed that a persistent Appium server tends to break after a few runs. This can be remedied by restarting the Appium server for each app, though that adds a bit of overhead. Nonetheless, after analysing a few hundred apps, the iPhone consistently got into a broken state where Appium couldn't communicate with the device anymore but it also wasn't possible to uninstall or start apps manually through the UI anymore. The Appium developers describe known issues with the underlying WebDriverAgent on real devices [@murchieREADMEMdAppiumxcuitestdriver2022]. We don't know whether these would also cause the problems we saw in iOS itself. Either way, they could be remedied by manually restarting the device, which then also required reapplying the jailbreak.
    * For some reason, the first `findElements()` call in a session doesn't find elements inside webviews. As a workaround, we can just do any `findElements()` call with results we don't care about first.
    * We disable several of the Appium features, namely automatically starting apps, waiting for their launch, and resetting, as those are intended for software testing and not flexible enough for the purposes of this thesis. Instead, we use the more flexible platform APIs described before.

## Traffic Collection

* mitmproxy
* Certification pinning bypasses
* We execute apps for one minute and record their network traffic.
* For that, we use a mitmproxy addon that stores encountered requests, as well as their headers and cookies in a Postgres database.
* Afterwards, we check whether the app is still running and discard the results otherwise. This is necessary because some apps quit immediately after launch, either because they detected that the device we're using is rooted/jailbroken and they consider that a security problem (often the case for banking apps, for example) or because of problems with the certificate pinning bypass by Objection on Android.
* Background noise filtering
    * https://support.apple.com/en-us/HT210060

## App Dataset

### App Selection

* To get a sufficient amount of apps, on both platforms we cannot just rely on the overall top charts as they don't contain enough apps. Instead, we rely on the top charts per category and merge the results.

TODO: List available categories per platform?

#### Android {#sec:app-selection-android}

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

#### iOS {#sec:app-selection-ios}

* Apple offers an [RSS feed generator](https://rss.applemarketingtools.com/) for the top charts of various media types they sell (including apps). Using that, it is possible to obtain an XML or JSON file (despite the tool's name) of the top free or top paid apps per country on the App Store. The generator only returns up to 50 apps, but it is possible to retrieve up to 200 apps by manually adjusting the result limit parameter in the URL: `https://rss.applemarketingtools.com/api/v2/de/apps/top-free/200/apps.json`. Requesting more than 200 apps will result in an internal server error.
* It used to be possible to get up to 1,200 top apps through `https://itunes.apple.com/WebObjects/MZStore.woa/wa/topChartFragmentData` endpoint that was used in old version of the iOS App Store [@johnsonAnswerHowGet2015]. However, that endpoint now only provides the top 100 apps.
* iTunes on Windows^[Newer versions of iTunes don't include support for the iOS App Store anymore, but Apple offers a special, unsupported but continuing to work as of the time of writing, version of iTunes (12.6.5.3) that still contains this feature and doesn't prompt the user to update to newer versions: <https://support.apple.com/HT208079>] can however display top charts for each category (called “genre” by Apple), with up to 200 results each. Observing the iTunes' network traffic when loading these pages revealed the following endpoint: `https://itunes.apple.com/WebObjects/MZStore.woa/wa/viewTop?cc=de&genreId=36&l=en&popId=27`
* The `cc` and `l` GET parameters control the country and language respectively.
* The `popId` parameter determines the type of top chart returned, with the following possible values (again determined by observing the iTunes network traffic): `27` (top free apps for iPhone), `30` (top paid apps for iPhone), `38` (top grossing apps for iPhone), `44` (top free apps for iPad), `46` (top grossing apps for iPad), `47` (top paid apps for iPad).
* Finally, the `genreId` parameter controls the category the returned top list is for. A list of all possible categories on iTunes can be retrieved from the `https://itunes.apple.com/WebObjects/MZStoreServices.woa/ws/genres` endpoint [@appleinc.GenreIDsAppendix2019]. `36` is the first-level category for all apps on the App Store. The second-level then has the actual app categories, e.g. `6000` for “Business”. There are also third-level categories but only for “Games” and “Newsstand”, so they are excluded here.
* In addition to the GET parameters, the `X-Apple-Store-Front` header also needs to be set. It consists of between one and three numbers and has the following format: `<country>-<language>,<platform>` (only `<country>` is required, the others can be left off). Setting `<country>` to `143443` means Germany for example; a list of possible countries used to be available in the iTunes affiliate partner documentation and can still be accessed through the Internet Archive [@appleinc.AdvancedPartnerLinking2019]. Among the available values for `<language>` are `1` (US English), `2` (British English), `3` (French), and `4` (German) [@olbaumHowITunesSelects2006; @konsumerAnswerWhatDoes2019]. It is not possible to combine country and language arbitrarily, for example setting US English as the language but German as the country does not work, where as British English does work for Germany. Finally, the `<platform>` values determines the Apple application the request is (supposedly) coming from, with `28` meaning iTunes 12 for example [@zhoufykScrapeRatingsITunes2019].
* The endpoint's response format changes depending on the platform set. When setting a graphical client like iTunes, an HTML site will be returned that contains a script element which assigns the actual API return value to `its.serverData`. Through trial and error, we discovered that setting the platform to `26` or `29` makes the endpoint instead return the API result directly as JSON, making it a lot easier to consume programmatically.
* In this result, `$.storePlatformData.lockup.results` then has a list of the respective top apps and their associated metadata. However this list only contains 84 results. To get the full list of 200 apps, one has to use `$.pageData.segmentedControl.segments[0].pageData.selectedChart.adamIds` instead, which is a list of the numerical app IDs without metadata.
* Done on 2022-03-22:
    * With all found apps: Apps before deduplication: 5205, Apps after deduplication: 4968
    * Top 100 per category: Apps before deduplication: 2605, Apps after deduplication: 2486

### App Acquisition

TODO: Download process on Android already well documented and implemented in various tools (TODO: cite), so we omit a description of it here and only describe the existing tool we use. Not the case on iOS however, so that is explained in detail.

#### Android

To download Android apps from the Google Play Store, we use [PlaystoreDownloader](https://github.com/ClaudiuGeorgiu/PlaystoreDownloader/). For this, a Google account is necessary that needs to be prepared with these steps [@georgiuREADMEMdPlaystoreDownloader2022]:

1. Enable two-factor authentication for the Google account.
2. Create an Android Emulator with Google Play support, use the Google account to login with that emulator, and download at least one app from the Play Store.
3. Install the [Device ID app](https://play.google.com/store/apps/details?id=com.evozi.deviceid) and use that to read the emulator's assigned “Google Service Framework (GSF) ID” there.
4. Create an [app password](https://myaccount.google.com/apppasswords) for the Google account.
5. Temporarily [allow signing in from new devices](https://accounts.google.com/DisplayUnlockCaptcha).
6. Update PlaystoreDownloader's `credentials.json` file with the correct `USERNAME` (the full email address of the account), `PASSWORD` (the app password generated before), and `ANDROID_ID` (the ID read using the Device ID app).

We then use a bash script to download the top 100 apps per category as collected in [@sec:app-selection-android]. Nowadays, many apps on the Play Store are distributed as so-called Android app bundles. This means that the app isn't bundled as a single `.apk` file but instead consists of multiple `.apk` files to allow Google to optimize app delivery for different devices [@androidopensourceprojectcontributorsAndroidAppBundles2022]. We pass the `-s` flag to PlaystoreDownloader to also download these so-called split APKs.  
If downloading fails for five or more consequtive apps, the script pauses for as many minutes to avoid exceeding potential undocumented rate limits in the Play Store endpoints.

The download script ran between March 22, 2022 at 18:54 and March 23, 2022 at 17:54. For 108 apps, the download failed. In all of these cases, the error code was `DF-DFERH-01`. Trying to download the failed apps through other APK download tools was unsuccessful as well. Viewing them in the Play Store on the emulator used to prepare the Google account showed the following error message: "Your device isn't compatible with this app." These apps were excluded from the analysis.

#### iOS

Prior to this thesis, there was no reliable automated way to download arbitrary iOS apps as IPA files. Older versions of iTunes supported manually downloading iOS apps as a native feature [@pearsonWhereIOSApps2011], which previous research on this topic leveraged by way of an [AutoHotkey script](https://github.com/OxfordHCC/platformcontrol-ios-downloader/blob/b6a2038e57863bbdf6b98304883cf698c1579db8/instrumentor.ahk) [@kollnigAreIPhonesReally2022]. Apple has since ended support for downloading iOS apps through iTunes but the feature continues to work in iTunes 12.6.5.3 for the time being [@appleinc.DeployAppsBusiness2019]. [3uTools](http://3u.com/), a third-party program for managing iOS devices, also includes the capability to download iOS apps [@3utoolsHowDownloadApps2017]. We confirmed through traffic analysis that is uses the same endpoints as iTunes.  
These days, it is still possible to download IPA files using [Apple Configurator](https://support.apple.com/apple-configurator), a program for companies that need to manage many iOS devices which temporarily stores the IPA files of provisioned apps on the user's computer [@andersonHowDownloadIPA2020]. This however only works for apps that are already "purchased" by the user's Apple ID and cannot be used to acquire new apps. The same applies for [iMazing](https://imazing.com/), another third-party iOS device management software that can also only download already purchased apps [@digidnasarlDownloadInstallBack2022] as it internally uses the same endpoints as Apple Configurator.

Thus, none of these methods provide a reliable way to download large amounts of iOS apps as needed for this thesis. Finally, [IPATool](https://github.com/majd/ipatool) is the only command line tool the author is aware of for downloading IPA files but it was previously also only able to download already purchased apps as it used the same Apple Configurator endpoints. Based on reverse-engineering the other described tools through network analysis, we were able to extend IPATool to also support purchasing new apps and use IPATool for this analysis. We contributed our changes back to IPATool^[See this pull request: <https://github.com/majd/ipatool/pull/51>] and they are already part of a [new release of the software](https://github.com/majd/ipatool/releases/tag/v1.1.0).

With our changes, the flow for downloading apps through IPATool now looks like this (the requests are incomplete here, for a more detailed breakdown of the full requests see Appendix TODO) [@alfhailyMajdIpatool1b65463007b7e5a160d1c83e32d92f4e18cde6da2022]:

1. IPATool first requests the app metadata to find out the numerical app ID for the given bundle ID:

   ```placeholders
   GET https://itunes.apple.com/lookup?entity=software&media=software
           &bundleId=<bundle ID>&country=<country code>&limit=1 HTTP/2.0
   ```

   The response is a JSON object where `$.results[0].trackId` is the numerical app ID.
2. It then logs in with a unique ID for the device, which is its MAC address without the colons, and the given Apple ID in the POST body:

   ```placeholders
   POST https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate
            ?guid=<device GUID> HTTP/1.1
   ```

   It uses an Apple Configurator user agent for this instead of an iTunes one. The reason is that authenticating for iTunes requires an additional `X-Apple-ActionSignature` header and the process for generating that is not known.

   The response sets the authentication cookies.
3. Now authenticated, IPATool can try to purchase the desired app for the Apple ID through an endpoint used by iTunes, specifying the numerical app ID as `salableAdamId` in the POST body:

   ```placeholders
   POST https://buy.itunes.apple.com/WebObjects/MZBuy.woa/wa/buyProduct HTTP/1.1
   ```

   This request will fail with a status code of 500 if the Apple ID already owns the app. This can simply be ignored.
4. If the previous request had set an iTunes user agent (and corresponding authentication cookies for iTunes), the reply would have already contained the download link for the IPA. For an Apple Configurator user agent however, this is not the case. Thus, IPATool needs to use the Apple Configurator endpoint for downloading already owned apps, again specifying the numerical app ID as `salableAdamId` in the POST body:

   ```placeholders
   POST https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa
            /volumeStoreDownloadProduct?guid=<device GUID> HTTP/1.1
   ```

   The response is a PLIST, where `$.songList[0].URL` is the download URL for the IPA file.
5. With that, IPATool can actually download the IPA file:

   ```placeholders
   GET https://iosapps.itunes.apple.com/itunes-assets/<path>/<filename>.ipa
           ?accessKey=<unique access key> HTTP/1.1
   ```
6. Finally, IPATool signs the IPA file. The signature is contained in `$.songList[0].sinfs[0].sinf` of the response from the `volumeStoreDownloadProduct` endpoint. It needs to be base64-decoded and written to `/Payload/<app name>.app/SC_Info/<app name>.sinf`{.placeholders} of the IPA file (an IPA file is just a ZIP archive).

   IPATool also fills the `/iTunesMetadata.plist` file in the IPA with the data in `$.songList[0].metadata` from the `volumeStoreDownloadProduct` response, additionally appending the `apple-id` and `userName` properties, both set to the user's Apple ID email address.

We made one additional change to IPATool: As the top list data we gathered in [@sec:app-selection-ios] already has the numerical app IDs, we patched out the code for getting them from the bundle IDs, thus eliminating the first step from above^[The code of our patched version is available at: <https://github.com/baltpeter/ipatool/tree/b_dev>].

We then also use a bash script to download the top 100 apps per category, just like on Android. In addition to the steps described there, the script also requests an app's privacy labels for [@sec:method-privacy-labels] immediately after downloading it through the following request:

```placeholders
GET https://amp-api.apps.apple.com/v1/catalog/DE/apps/<numerical app ID>
        ?platform=iphone&extend=privacyDetails&l=en-gb HTTP/2.0

Authorization: Bearer <token>
```

A token for this request can be obtained by visiting any app on the web version of the iOS App Store and observing the network traffic while clicking the "See Details" link next to "App Privacy".

The download script ran between March 22, 2022 at 21:00 and March 25, 2022 at 12:06. The download delayed due to an App Store downtime. We also noticed that after downloading around 300 apps, the `buyProduct` endpoint would still return a valid response but the app would not appear in the Apple ID's list of purchased apps, causing the subsequent `volumeStoreDownloadProduct` request to fail. This also applied to downloading apps through the App Store on the iPhone. After a few days, it would work again. To work around this problem, we used two Apple IDs for the download^[In general, iOS will only allow apps signed for the logged-in Apple ID to run. If apps signed for another Apple ID are opened, a prompt saying 'To open “`<app>`{.placeholders}”, sign in with the Apple ID that purchased it.' is displayed. If one signs in with the other Apple ID in this prompt, running apps from both Apple IDs is subsequently possible (but the second Apple ID doesn't seem to be displayed anywhere in the UI).].

Downloading failed for five apps. Manually checking revealed that they had all since been taken down from the App Store. Those apps were excluded from the analysis.

---

TODO:

* Getting app metadata from file (id, version)
