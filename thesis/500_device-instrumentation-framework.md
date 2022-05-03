# Device Instrumentation Framework

We developed a framework for automated instrumentation of Android and iOS apps for this analysis, using an emulator on Android and a physical device on iOS. The framework can manage (install, run, and uninstall) apps, set app permissions and extract app preferences, collect the device network traffic (including HTTPS and certificate-pinned traffic) while an app is running, as well as analyse and interact with elements displayed on screen. It builds on and extends previous work on data protection in mobile apps that we conducted and participated in [@altpeterTheyTrackAutomated2021; @altpeterIOSWatchingYou2021].  
The framework is written in TypeScript running on Node.js. The full source code is available on GitHub: <https://github.com/baltpeter/thesis-mobile-consent-dialogs>

We also present an approach to extract top chart data from the Play Store on Android and App Store on iOS, as well as download the corresponding apps.

## Traffic Collection

To record the apps' network traffic, we use [*mitmproxy*](https://mitmproxy.org/), an open-source set of proxy tools written in Python, which can already deal with HTTPS traffic given its certificate authority is installed in the system certificate stores [@cortesiMitmproxyFreeOpen2021]. However, we also need to deal with apps that implement certificate pinning. For that, we use [*objection*](https://github.com/sensepost/objection) on Android and [*SSL Kill Switch 2*](https://github.com/nabla-c0d3/ssl-kill-switch2) on iOS. These hook known certificate pinning functions provided by the OS itself, in common libraries, and even some custom implementations in apps. Nonetheless, it is still possible that apps use other pinning mechanisms not recognized by them. In those cases, we will miss the corresponding requests.

We execute apps for one minute and record their traffic in the meantime. For that, we use a mitmproxy add-on that stores the encountered requests, as well as their headers and cookies, in a PostgreSQL database. After the one-minute timeout has expired, we check whether the app is still running and discard the results otherwise. This is necessary because some apps quit immediately after launch, either because they detected that the device we are using is rooted/jailbroken and they consider that a security problem (often the case for banking apps, for example), or because of problems with the certificate pinning bypass by objection on Android (see [@sec:discussion-limitations]).

Using mitmproxy, we can only record the whole device's network traffic and not an individual app's traffic. Both Android and iOS regularly send requests to Google and Apple, respectively, in the background, doing connectivity checks, time synchronisation, and their own tracking for example^[Apple at least provides a list explaining most of the background requests: <https://support.apple.com/en-us/HT210060>]. We need to filter out this background noise. To do so, we recorded the network traffic from idle devices for several days and created an SQL view to filter out all requests from these runs. For some endpoints, it is difficult or even impossible to figure out whether a request was caused by an app or by the OS, e.g. when both Android itself and apps use the same Google trackers. In those cases, we have opted to rather remove too much than too little traffic to avoid wrongly attributing OS traffic to apps. The full list of filters we employ can be seen in [@Sec:appendix-filtered-requests-sql].

## Device Management Automation {#sec:instrumentation-device}

For managing the devices, we have implemented platform-specific interfaces that provide the following common commands for both Android and iOS:

Ensure device
:   On Android, this starts the emulator and waits for it to finish booting. For that, it reads the boot animation state using `adb -e shell getprop init.svc.bootanim`{.sh} and waits until that returns `stopped` [@sprynAutomatedAndroidEmulator2020].  
    We also run this command when the emulator has stopped responding (this seems to be caused by emulator bugs that happen with some apps). Thus, it first stops a potential previous running emulator before starting a new one.

    On iOS, this is a no-op since we are using a physical device that we cannot start automatically as the jailbreak requires manual steps (in particular, putting the device into DFU mode). The iPhone has to be started and jailbroken before the analysis is run (see [@sec:instrumentation-device-prep]).

Reset device
:   On Android, this uses the emulator's snapshot features [@androidopensourceprojectcontributorsStartEmulatorCommand2020] to restore the emulator into a clean state by loading a predefined snapshot.  
    After that, it checks whether Frida is already running and starts it otherwise.

    On iOS, this is once again a no-op since it is not possible to reset the device automatically either. Instead, we rely on the *uninstall app* and *clear stuck modals* commands to put the device into a clean state again.

Clear stuck modals
:   Sometimes, modals or opened browser windows are stuck on the screen after uninstalling an app. On Android, we can get rid of those by pressing the back button followed by the home button. This is done through the `adb shell "input keyevent $event_number"`{.sh} command, where `4` is the event number for the back button, and `3` the one for the home button [@lioncoderAnswerADBShell2011].

    On iOS, we use [*Activator*](https://cydia.saurik.com/package/libactivator/) and the `activator send libactivator.system.clear-switcher`{.sh} and `activator send libactivator.system.homebutton`{.sh} commands [@geekdadaURLSchemes2016]. We send those to the device through SSH.

Install or uninstall app
:   Nowadays, many apps on the Play Store are distributed as *Android App Bundles*. This means that the app is not bundled as a single `.apk` file but instead consists of multiple `.apk` files, so-called *split APKs*, to allow Google to optimize app delivery for different devices [@androidopensourceprojectcontributorsAndroidAppBundles2022]. Split APKs can be correctly installed by passing all their parts to the `adb install-multiple`{.sh} command. We also pass the `-g` flag which grants all permissions to the app [@androidopensourceprojectcontributorsAndroidDebugBridge2022].  
    To uninstall apps, we use `adb shell "pm uninstall --user 0 $appId"`{.sh} [@neverever415AnswerAdbShell2012]. In the case of an error, unlike `adb uninstall`{.sh}, this allows us to determine whether there was an actual problem or the app just wasn't installed to begin with.

    On iOS, we use the `ideviceinstaller --install`{.sh} and `ideviceinstaller --uninstall`{.sh} commands from [*libimobiledevice*](https://libimobiledevice.org/), an open source cross-platform library for interacting with iOS devices.

Set app permissions
:   As we want to find out all data apps would transmit if given the opportunity, we need to give them all permissions. Granting an operating system permission only refers to the local device access the apps have and not to data protection, thus it cannot be considered consent under the GDPR or ePD.

    On Android, we have already granted all runtime permissions through the `-g` flag to `adb install`. This does not, however, include so-called dangerous permissions like reading phone numbers or SMS messages. To grant those, we first obtain a list of dangerous permissions by using the command `adb shell "pm list permissions -g -d -u"`{.sh}, and then grant them individually using the command `adb shell "pm grant $appId $permissionId"`{.sh} [@latifAnswerListADB2020].

    On iOS, there is no intended way to grant permissions other than through the GUI. We discovered that permission data is stored in the `access` table of an SQLite database that is located at `/private/var/mobile/Library/TCC/TCC.db`. A list of possible permission IDs can be reconstructed by using `/System/Library/PrivateFrameworks/TCC.framework/en.lproj/Localizable.strings`, a translation file for the *Transparency, Consent, and Control* framework [@johnsonDeepDiveMacOS2021]. Setting the `auth_value` column to `2` grants the permission, setting it to `0` denies it. A list of which permissions we set can be found in [@tbl:appendix-ios-permissions] in [@Sec:appendix-figures-tables].

    The location permission is not handled by that table. To grant an app access to the location, we inject the following Frida script into the settings application:

    ```js
    ObjC.classes.CLLocationManager
        .setAuthorizationStatusByType_forBundleIdentifier_(
            authorization_status, app_id
        );
    ```

    The possible values for the authorization status are: `0` (ask every time), `2` (never), `3` (always), and `4` (while using the app)^[A value of `1` would mean that the status is restricted and cannot be changed by the user, e.g. due to parental controls [@appleinc.CLAuthorizationStatus2022].].

Set clipboard
:   To seed the clipboard, we again use Frida scripts. On Android, we inject the following script into the launcher process (`com.google.android.apps.nexuslauncher`):

    ```js
    var app_ctx = Java.use('android.app.ActivityThread').currentApplication()
        .getApplicationContext();
    var cm = Java.cast(
        app_ctx.getSystemService("clipboard"),
        Java.use("android.content.ClipboardManager")
    );
    cm.setText(Java.use("java.lang.StringBuilder").$new(text)); 
    ```

    On iOS, we inject the following script into the `SpringBoard` process:

    ```js
    ObjC.classes.UIPasteboard.generalPasteboard().setString_(text);
    ```

Start app
:   On Android, we start apps through objection. That way, we can enable early instrumentation for the certificate pinning bypasses and ensure we do not miss any requests [@jacobsEarlyInstrumentation2017].

    On iOS, SSL Kill Switch 2 is running system-wide and doesn't need to be manually injected into apps. We use the [*Open* package](http://cydia.saurik.com/package/com.conradkramer.open/), which enables us to start apps from the command line using the `open`{.sh} command, which we do via SSH.

Reset app
:   We need to run apps with dialogs multiple times so we can capture the different network traffic after accepting and rejecting them. This command also prepares the app for analysis. 

    The steps for that are the same on both platforms as they rely on the other commands:

    1. Uninstall the app if it was previously installed. This will also clear all app data and settings.
    2. Install the app.
    3. Set the desired app permissions.
    4. Clear any stuck modals.
    5. Seed the clipboard to a known value.
    6. Start the app.

Get app preferences
:   This fetches the app's preferences from the operating system's per-app storage interfaces (`SharedPreferences` on Android, and `NSUserDefaults` on iOS) by injecting the Frida scripts described in [@sec:cd-situation-mobile-tcf] and converting their results to JSON. The preferences contain the IAB TCF data.

Get app version
:   On Android, this returns an APK's version by running `aapt dump badging $apk_path`{.sh} and extracting the `versionName` field [@androidopensourceprojectcontributorsAAPT22020].

    On iOS, we use the [*ipa-extract-info*](https://github.com/nowsecure/ipa-extract-info) library to parse the IPA files and then read the version from `$.info.CFBundleShortVersionString`.

## App Instrumentation

For reading and interacting with elements on the screen, we leverage [*Appium*](http://appium.io/), an open source test automation framework. Appium provides a common interface over platform-specific user interface testing APIs, in particular *UiAutomator2* on Android and *XCUITest* on iOS [@lippsIntroduction2022]. This way, we can use the same code for both platforms.

We disable several of Appium's features, namely automatically starting apps, waiting for their launch, and resetting, as those are intended for software testing and not flexible enough for the purposes of this thesis. Instead, we use our own platform APIs described in [@sec:instrumentation-device].

The Appium docs previously mentioned that Appium does not work with jailbroken iOS devices, though we found that to be wrong^[We have submitted a correction and the docs have since been changed: <https://github.com/appium/appium/issues/16211>]. We were however not able to rely on Appium's automatic configuration for iOS and had to resort to using the fully manual configuration [@matsuoXCUITestRealDevices2021]. We additionally had to pass the `-allowProvisioningUpdates` flag to `xcodebuild`, which the docs previously did not mention^[We have also submitted a correction that has since been incorporated for that: <https://github.com/appium/appium/issues/16212>, <https://github.com/appium/appium/pull/16215>]. This may be due to the fact that we are using a free Apple developer account.

Further, we noticed that a persistent Appium server tends to break after a few runs on iOS. This can be mitigated by restarting the Appium server for each app, though that adds a bit of overhead. Nonetheless, after analysing a few hundred apps, the iPhone consistently got into a broken state where Appium couldn't communicate with the device anymore, and sometimes it was not possible to uninstall or start apps manually through the UI anymore, either. The Appium developers describe known issues with the underlying WebDriverAgent on real devices [@murchieREADMEMdAppiumxcuitestdriver2022]. We do not know whether these would also cause the problems we saw in iOS itself. Either way, they could be remedied by manually restarting the device, which then also required reapplying the jailbreak.

Finally, we noticed that the first `findElements()` call in a session does not find elements inside webviews, for some reason. As a workaround, we found that we can do an initial bogus `findElements()` call before any other ones and discard its results.

## Device Preparation {#sec:instrumentation-device-prep}

For Android, Google has long offered an established emulator that is well supported by tooling. It is possible to install arbitrary apps into the emulator. Thus, we can utilise it for our analysis. We use Android 11 on the x86_64 architecture. This provides a good compromise between performance and compatibility, as the emulator provides hardware acceleration support for x86 [@androidopensourceprojectcontributorsConfigureHardwareAcceleration2021] and we can still run apps only compiled for ARM as the emulator is capable of translating ARM instructions to x86 [@hazardRunARMApps2020]. 

While Apple also offers an iOS Simulator, it cannot run apps packaged for distribution as downloaded from the App Store [@InstallingIpaApp2021; @grgAnswerHowCan2013]. We would need to have the apps' source code to create a development build, which is not feasible. And even then, the iOS Simulator is much more locked down than the Android Emulator and does not allow us to access everything we would need for the analysis. There are a number of commercial providers that offer running native iOS apps like *Appetize.io* and *RunThatApp*, but those only resell the iOS Simulator and are thus suitable either [@appetize.iollcUploadingApps2022; @runthatapp.cominc.RunThatAppFileSubmission2021].  
As such, we need to use a real iPhone for the analysis. We are using an iPhone 7 that is running iOS 14.8. The choice of the iOS version is heavily constrained by two factors: jailbreak and device availability. As of the time of writing, the newest version of iOS is 15.4.1, but no jailbreak, which is necessary for the kinds of instrumentation we are doing, is available for iOS 15 yet [@emiylIPhone2022; @bouchardCoolStarConfirmsThat2022]. At the same time, Apple heavily restricts the versions that can be installed on an iPhone. It is currently only possible to upgrade to the very latest version, iOS 15.4.1, and no downgrades are possible at all^[It _is_ possible to downgrade to any version for which one has backed up Apple's signatures (so-called SHSH blobs), but those are tied to a specific device [@pj09FaqDowngrading2021].] [@danthemann15SHSH2022]. Thus, one has to resolve to buying used devices that happen to not have been upgraded yet by their previous owner. This makes choosing a particular version of iOS to base the analysis on practically impossible. The only requirement we were able to impose is a version of at least 14.5 (which introduced the *App Tracking Transparency* changes [@appleinc.IOS14Offers2021]) and lower than 15.0 (so a jailbreak is available).

In the following, we give an overview of the steps needed to prepare the device/emulator for instrumentation.

### Android

On Android, the general device setup steps are:

1. Install the mitmproxy certificate as a root certificate authority. On newer versions of Android, including Android 11, which we are using, this requires starting the emulator with the `-writable-system` flag, disabling *Android Verified Boot* (AVB) and *device-mapper-verity* (dm-verity), and copying the certificate to the `/system/etc/security/cacerts/` folder [@joseAnswerAdbRemount2020; @ropnopConfiguringBurpSuite2018; @0x10f2cInterceptingTrafficAndroid2019].
2. Install Frida server 15.1.12.
3. Uninstall unnecessary Google apps to avoid their background traffic.
4. Disable Android's default captive portal checks [@yanAnswerCaptivePortal2017] to further reduce background noise. 

### iOS

On iOS, the steps are:

1. Jailbreak the device using [*checkra1n*](https://checkra.in/) 0.12.4 beta.
2. Install the following Cydia packages: [*Activator*](https://cydia.saurik.com/package/libactivator/), [*SSL Kill Switch 2*](https://github.com/nabla-c0d3/ssl-kill-switch2), [*Frida*](https://frida.re/docs/ios/#with-jailbreak), [*Open*](http://cydia.saurik.com/package/com.conradkramer.open/), [*OpenSSH*](https://cydia.saurik.com/package/openssh/), [*sqlite3*](http://apt.bingner.com/debs/1443.00/sqlite3_3.24.0-1_iphoneos-arm.deb).
3. Adjust the device settings to keep background traffic to a minimum, disabling background app refresh, automatic OS updates, iPhone analytics, and automatic app downloads and updates.
4. Uninstall all unnecessary third-party apps to avoid their background traffic.
5. Configure the machine mitmproxy is run on as the proxy and import mitmproxy's profile to trust its certificate authority [@ibanezInterceptingNetworkTraffic2019].

### Honey Data {#sec:instrumentation-honey-data}

On both platforms, we plant honey data so we can detect if apps transmit this data. We use randomly generated values with sufficient entropy to make sure they cannot appear in traffic by chance. We also read relevant device identifiers that apps may track. [@tbl:instrumentation-honey-data] shows the honey data we use.

| Value              | Kind                    | Notes        |
|--------------------|-------------------------|--------------|
| Contacts           | set manually            |              |
| Location           | set through Appium      |              |
| Messages           | set manually            |              |
| Calls              | set manually            | Android only |
| Clipboard          | set through Frida       |              |
| Calendar           | set manually            | iOS only     |
| Reminders          | set manually            | iOS only     |
| Notes              | set manually            | iOS only     |
| Health details     | set manually            | iOS only     |
| Apple Home data    | set manually            | iOS only     |
| WiFi SSID          | set manually            |              |
| Device name        | set manually            |              |
| Phone number       | set manually            | Android only |
| Operating system   | device parameter        |              |
| Device model       | device parameter        |              |
| Serial number      | device parameter        |              |
| MAC addresses      | device parameter        |              |
| BSSID              | device parameter        |              |
| Advertising ID     | set automatically by OS |              |
| Local IP addresses | set automatically by OS |              |

:   Overview of the honey data we set on the devices. Most values are either manually placed on the device by us beforehand or already present on the system. We automatically set the location through Appium and seed the clipboard through Frida. Some values are only present on one of the platforms. {#tbl:instrumentation-honey-data}

## App Dataset

To give an accurate picture of consent dialogs in mobile apps, we need a large dataset of apps on Android and iOS. We restrict our dataset to apps from the respective platform's top charts to only include apps that are actually commonly used in the wild and avoid potential outliers in insignificant apps.

### App Selection

To get a sufficient amount of apps, on both platforms we cannot just rely on the overall top charts as they do not contain enough apps. Instead, we rely on the top charts per category and merge the results. A list of the categories is given in [@tbl:appendix-categories] in [@Sec:appendix-figures-tables].

#### Android {#sec:app-selection-android}

Google does not offer an API for the top apps from the Play Store. The Play Store web UI does have [top lists for apps and games](https://play.google.com/store/apps/top), though, distinguishing between "top for 0€", "top selling", and "top grossing", with 200 apps each. Using only those would yield at most 400 free apps (assuming the top free lists for apps and games are disjunct), which is not sufficient for this thesis. Going through the pages for individual categories^[e.g. <https://play.google.com/store/apps/category/TOOLS>] offers various sublists on different topics, but those are not top charts and the number of apps in them varies wildly between a handful and up to around 50.
Various third-party companies do sell top chart APIs for the Play Store with more results (e.g. [@appfiguresinc.TopAppsAndroid2020; @sensortowerinc.TopGrossingApps2022]), but they don't disclose how those are compiled, and it is preferable to rely on an official source.

We found that Google _does_ in fact publish top charts per category, though those are not linked anywhere in the web UI as far as we can tell and can only be found through search engines. Those lists again contain 200 apps each. The links for those pages follow this pattern:

```placeholders
https://play.google.com/store/apps/top/category/<category ID>?gl=<country code>
```

The category IDs can be determined from the links in the category dropdown at the top of the web page, which are of the form: `https://play.google.com/store/apps/category/<category ID>`{.placeholders}. From the category top pages, one has to click on the "top for 0€" link (which contains obfuscated parameters and thus can't be constructed directly by us).

Knowing that, we were able to write a scraper that extracts the top free apps per category using Microsoft's [*Playwright*](https://playwright.dev/) browser automation framework. The scraper iterates over all category IDs and, for each one:

1. Visits the top list page.
2. Clicks the "top for 0€" link.
3. Continues scrolling to the bottom of the page until it doesn't get larger anymore (to defeat infinite scrolling as results are loaded dynamically using JavaScript^[It would probably be possible to use the underlying network requests to extract the top list data directly without scraping, but those requests are heavily obfuscated.]).
4. Extracts ID, name and top list position for each app on the page.

We scraped the top apps on Google Play on March 22, 2022. Counting all results, we found 6,970 apps in total, with 6,817 apps remaining after deduplication. For this analysis, we restrict our dataset to the top 100 apps per category. For that, we found 3,500 apps in total, with 3,421 apps remaining after deduplication.

#### iOS {#sec:app-selection-ios}

Apple offers an [RSS feed generator](https://rss.applemarketingtools.com/) for the top charts of various media types they sell (including apps). Using that, it is possible to obtain an XML or JSON file (despite the tool's name) of the top free or top paid apps per country on the App Store. The generator only returns up to 50 apps, but it is possible to retrieve up to 200 apps by manually adjusting the result limit parameter in the URL: `https://rss.applemarketingtools.com/api/v2/de/apps/top-free/<limit>/apps.json`{.placeholders}  
Requesting more than 200 apps will result in an internal server error.

It used to be possible to get up to 1,200 top apps through an endpoint that was used in old versions of the iOS App Store: `https://itunes.apple.com/WebObjects/MZStore.woa/wa/topChartFragmentData` [@johnsonAnswerHowGet2015]. However, that endpoint now only provides the top 100 apps. iTunes on Windows^[Newer versions of iTunes don't include support for the iOS App Store anymore, but Apple offers a special, unsupported (but continuing to work as of the time of writing) version of iTunes (12.6.5.3) that still contains this feature and doesn't prompt the user to update to newer versions: <https://support.apple.com/HT208079>] can however display top charts for each category (called “genre” by Apple), with up to 200 results each.

Observing iTunes' network traffic when loading these pages revealed the following endpoint:

```placeholders
GET https://itunes.apple.com/WebObjects/MZStore.woa/wa/viewTop
    ?cc=<country code>&genreId=<genre ID>&l=<language code>&popId=<top list type>
```

The `cc` and `l` GET parameters control the country and language, respectively. The `popId` parameter determines the type of top chart returned, with the following possible values (again determined by observing the iTunes network traffic): `27` (top free apps for iPhone), `30` (top paid apps for iPhone), `38` (top grossing apps for iPhone), `44` (top free apps for iPad), `46` (top grossing apps for iPad), `47` (top paid apps for iPad).  
Finally, the `genreId` parameter controls the category the returned top list is for. A list of all possible categories can be found at `https://itunes.apple.com/WebObjects/MZStoreServices.woa/ws/genres` [@appleinc.GenreIDsAppendix2019]. `36` is the first-level category for all apps on the App Store. The second level then has the actual app categories, e.g. `6000` for “Business”. There are also third-level categories but only for “Games” and “Newsstand”, so they are excluded here.

In addition to the GET parameters, the `X-Apple-Store-Front` header also needs to be set. It consists of between one and three numbers and has the following format: `<country>-<language>,<platform>`{.placeholders} (only `<country>`{.placeholders} is required, the others can be left off). Setting `<country>`{.placeholders} to `143443` means Germany for example; a list of possible countries used to be available in the iTunes affiliate partner documentation and can still be accessed through the Internet Archive [@appleinc.AdvancedPartnerLinking2019]. Among the available values for `<language>`{.placeholders} are `1` (US English), `2` (British English), `3` (French), and `4` (German) [@olbaumHowITunesSelects2006; @konsumerAnswerWhatDoes2019]. It is not possible to combine country and language arbitrarily, for example setting US English as the language but Germany as the country does not work, whereas British English does work for Germany. Finally, the `<platform>`{.placeholders} value determines the Apple application the request is (supposedly) coming from, with `28` meaning iTunes 12 for example [@zhoufykScrapeRatingsITunes2019].

The endpoint's response format changes depending on the platform set. When setting a graphical client like iTunes, an HTML site will be returned that contains a script element which assigns the actual API return value to `its.serverData`. Through trial and error, we discovered that setting the platform to `26` or `29` makes the endpoint instead return the API result directly as JSON, making it a lot easier to consume programmatically.

In this result, `$.storePlatformData.lockup.results` then has a list of the respective top apps and their associated metadata. However, this list only contains 84 results. To get the full list of 200 apps, one has to use `$.pageData.segmentedControl.segments[0].pageData.selectedChart.adamIds` instead, which is a list of the numerical app IDs without metadata.

We retrieved the top charts of the iOS App Store on March 22, 2022. Counting all results, we found 5,205 apps in total, with 4,968 apps remaining after deduplication. Again restricting our dataset to the top 100 apps per category, we found 2,605 apps in total^[One category, "Catalogues", only has five apps in its top charts, which explains the count not being divisible by 100.], with 2,486 apps remaining after deduplication.

### App Acquisition

The download process on Android is already well known and implemented in various tools^[Examples include: <https://github.com/ClaudiuGeorgiu/PlaystoreDownloader>, <https://github.com/onyxbits/raccoon4>, <https://github.com/89z/googleplay>, <https://github.com/rehmatworks/gplaydl>, and <https://github.com/matlink/gplaycli>], so we omit a description of it here and only describe the existing tool we use. This is not the case on iOS however, so that is explained in detail.

#### Android

To download Android apps from the Google Play Store, we use [*PlaystoreDownloader*](https://github.com/ClaudiuGeorgiu/PlaystoreDownloader/). For this, a Google account is necessary that needs to be prepared with these steps [@georgiuREADMEMdPlaystoreDownloader2022]:

1. Enable two-factor authentication for the Google account.
2. Create an Android Emulator with Google Play support, use the Google account to login with that emulator, and download at least one app from the Play Store.
3. Install the [*Device ID* app](https://play.google.com/store/apps/details?id=com.evozi.deviceid) and use that to read the emulator's assigned *Google Service Framework (GSF) ID* there.
4. Create an [app password](https://myaccount.google.com/apppasswords) for the Google account.
5. Temporarily [allow signing in from new devices](https://accounts.google.com/DisplayUnlockCaptcha).
6. Update PlaystoreDownloader's `credentials.json` file with the correct `USERNAME` (the full email address of the account), `PASSWORD` (the app password generated before), and `ANDROID_ID` (the ID read using the Device ID app).

We then use a bash script to download the top 100 apps per category as collected in [@sec:app-selection-android]. We pass the `-s` flag to PlaystoreDownloader to correctly download split APKs.  
If downloading fails for five or more consecutive apps, the script pauses for as many minutes to avoid exceeding potential undocumented rate limits in the Play Store endpoints.

The download script ran between March 22, 2022 at 18:54 and March 23, 2022 at 17:54. For 108 apps, the download failed. In all of these cases, the error code was `DF-DFERH-01`. Trying to download the failed apps through other APK download tools was unsuccessful as well. Viewing them in the Play Store on the emulator used to prepare the Google account showed the following error message: "Your device isn't compatible with this app." These apps were excluded from the analysis.

#### iOS

Prior to this thesis, there was no reliable automated way to download arbitrary iOS apps as IPA files. Older versions of iTunes supported manually downloading iOS apps as a native feature [@pearsonWhereIOSApps2011], which previous research on this topic leveraged by way of an [AutoHotkey script](https://github.com/OxfordHCC/platformcontrol-ios-downloader/blob/b6a2038e57863bbdf6b98304883cf698c1579db8/instrumentor.ahk) [@kollnigAreIPhonesReally2022]. Apple has since ended support for downloading iOS apps through iTunes, but the feature continues to work in iTunes 12.6.5.3 for the time being [@appleinc.DeployAppsBusiness2019]. [*3uTools*](http://3u.com/), a third-party program for managing iOS devices, also includes the capability to download iOS apps [@3utoolsHowDownloadApps2017]. We confirmed through traffic analysis that it uses the same endpoints as iTunes.  
These days, it is still possible to download IPA files using [*Apple Configurator*](https://support.apple.com/apple-configurator), a program for companies that need to manage many iOS devices, which temporarily stores the IPA files of provisioned apps on the user's computer [@andersonHowDownloadIPA2020]. This however only works for apps that are already "purchased" (the same term is used for free apps) by the user's Apple ID and cannot be used to acquire new apps. The same applies for [*iMazing*](https://imazing.com/), another third-party iOS device management software that can also only download already purchased apps [@digidnasarlDownloadInstallBack2022], as it internally uses the same endpoints as Apple Configurator.

Thus, none of these methods provide a reliable way to download large amounts of iOS apps as needed for this thesis. Finally, [*IPATool*](https://github.com/majd/ipatool) is the only command line tool we are aware of for downloading IPA files, but it was previously also only able to download already purchased apps, since it used the same Apple Configurator endpoints. Based on extensive reverse-engineering of the other described tools through network analysis, we were able to extend IPATool to also support purchasing new apps and thus use IPATool for this analysis. We contributed our changes back to IPATool^[See this pull request: <https://github.com/majd/ipatool/pull/51>] and they are already part of a [new release of the software](https://github.com/majd/ipatool/releases/tag/v1.1.0).

With our changes, the flow for downloading apps through IPATool now looks like this (the requests are incomplete here for brevity) [@alfhailyMajdIpatool2022]:

1. IPATool first requests the app metadata to find out the numerical app ID for the given bundle ID:

   ```placeholders
   GET https://itunes.apple.com/lookup?entity=software&media=software
           &bundleId=<bundle ID>&country=<country code>&limit=1 HTTP/2.0
   ```

   The response is a JSON object, where `$.results[0].trackId` is the numerical app ID.
2. It then logs in with a unique ID for the device, which is its MAC address without the colons, and the given Apple ID in the POST body:

   ```placeholders
   POST https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa/authenticate
            ?guid=<unique device ID> HTTP/1.1
   ```

   It uses an Apple Configurator user agent for this instead of an iTunes one. The reason is that authenticating for iTunes requires an additional `X-Apple-ActionSignature` header and the process for generating that is not known.

   The response sets the authentication cookies.
3. Now authenticated, IPATool can try to purchase the desired app for the Apple ID through an endpoint used by iTunes, specifying the numerical app ID as `salableAdamId` in the POST body:

   ```placeholders
   POST https://buy.itunes.apple.com/WebObjects/MZBuy.woa/wa/buyProduct HTTP/1.1
   ```

   This request will fail with a status code of 500 if the Apple ID already owns the app^[By first doing a request to `https://se-edge.itunes.apple.com/WebObjects/MZStoreElements.woa/wa/buyButtonMetaData` and using the returned `buyParams` in the `buyProduct` request, this could be avoided. But in the context of IPATool, the 500 error is not a problem, so the extra request is not necessary.]. This can simply be ignored.
4. If the previous request had set an iTunes user agent (and corresponding authentication cookies for iTunes), the reply would have already contained the download link for the IPA. For an Apple Configurator user agent however, this is not the case. Thus, IPATool needs to use the Apple Configurator endpoint for downloading already owned apps, again specifying the numerical app ID as `salableAdamId` in the POST body:

   ```placeholders
   POST https://p25-buy.itunes.apple.com/WebObjects/MZFinance.woa/wa
            /volumeStoreDownloadProduct?guid=<unique device ID> HTTP/1.1
   ```

   The response is a PLIST, where `$.songList[0].URL` is the download URL for the IPA file.
5. With that, IPATool can actually download the IPA file:

   ```placeholders
   GET https://iosapps.itunes.apple.com/itunes-assets/<path>/<filename>.ipa
           ?accessKey=<unique access key> HTTP/1.1
   ```
6. Finally, IPATool signs the IPA file, which is necessary to run it on iOS devices. The signature is contained in `$.songList[0].sinfs[0].sinf` of the response from the `volumeStoreDownloadProduct` endpoint. It needs to be base64-decoded and written in the IPA file (which is just a ZIP archive) to `/Payload/<app name>.app/SC_Info/<app name>.sinf`{.placeholders}.

   IPATool also fills the `/iTunesMetadata.plist` file in the IPA with the `$.songList[0].metadata` data from the `volumeStoreDownloadProduct` response, additionally appending the `apple-id` and `userName` properties, both set to the user's Apple ID email address.

We made one additional change to IPATool: As the top list data we gathered in [@sec:app-selection-ios] already has the numerical app IDs, we patched out the code for getting them from the bundle IDs, thus eliminating the first step from above^[The code of our patched version is available at: <https://github.com/baltpeter/ipatool/tree/b_dev>].

We then also use a bash script to download the top 100 apps per category, just like on Android. In addition to the steps described there, the script also requests an app's privacy label for [@sec:method-privacy-labels] immediately after downloading it through the following request:

```placeholders
GET https://amp-api.apps.apple.com/v1/catalog/DE/apps/<numerical app ID>
        ?platform=iphone&extend=privacyDetails&l=en-gb HTTP/2.0

Authorization: Bearer <token>
```

A token for this request can be obtained by visiting any app on the web version of the iOS App Store and observing the network traffic while clicking the "See Details" link next to "App Privacy".

The download script ran between March 22, 2022 at 21:00 and March 25, 2022 at 12:06. The download was delayed due to an App Store downtime. We also noticed that after downloading around 300 apps, the `buyProduct` endpoint would still return a valid response, but the app would not appear in the Apple ID's list of purchased apps, causing the subsequent `volumeStoreDownloadProduct` request to fail. This also applied to downloading apps through the App Store on the iPhone. After a few days, it would work again. To work around this problem, we used two Apple IDs for the download^[In general, iOS will only allow apps signed for the logged-in Apple ID to run. If apps signed for another Apple ID are opened, a prompt saying 'To open “`<app>`{.placeholders}”, sign in with the Apple ID that purchased it.' is displayed. If one signs in with the other Apple ID in this prompt, running apps from both Apple IDs is subsequently possible (but the second Apple ID does not seem to be displayed anywhere in the UI).].

Downloading failed for five apps. Manual checking revealed that they had all since been taken down from the App Store. Those apps were excluded from the analysis.
