# Notes

## Apps

* Even with AppSync Unified, apps signed for another Apple ID don't work. Error: "To open “<app>”, sign in with the Apple ID that purchased it."
* Things that don't work:
    * https://github.com/akemin-dayo/AppSync
    * https://github.com/basti564/fakesigner
    * https://crazy90.com/CMSigner/
    * https://github.com/akemin-dayo/AppSync/tree/master/appinst
    * Removing `iTunesMetadata.plist` from the IPA.
    * Changing the Apple ID listed in `iTunesMetadata.plist`.
* Interestingly, if I _do_ sign in with the other Apple ID in the prompt, that doesn't seem to change the Apple ID associated with the phone. I seem to then be able to use apps purchased from _both_ accounts.

## Instrumentation

* Appium
    * iOS: XCUITest driver does work with free account and jailbroken device. Had to use manual configuration (https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/#full-manual-configuration) and additionally pass `-allowProvisioningUpdates` to `xcodebuild`. Problem: Developer certificate will expire after six days and has to be reissued, then I have to go through these steps again.
    * Android: Works just fine with the Emulator.
    * [Appium Inspector](https://github.com/appium/appium-inspector) very helpful for… inspecting apps and finding IDs, etc.
    * Might even be possible to use a real device cloud like BrowserStack.

### Steps for setting up Appium under iOS

based on: https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/ and https://makaka.org/unity-tutorials/test-ios-app-without-developer-account

0. Create an Apple developer account (free is fine) and use that to log into XCode.
1. Connect the iPhone via USB.
2. Start *XCode*. In the menu bar, click *Window* and *Devices and Simulators*. Ensure the iPhone is available there.
3. In a terminal, start `appium`.
4. Follow the steps at https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/#full-manual-configuration (full manual configuration).
5. Open *Appium Inspector* and create a session with the following desired capabilities to test:

  ```json
  {
    "appium:xcodeOrgId": "PUTGKYV8KZ",
    "appium:xcodeSigningId": "Apple Development",
    "appium:udid": "auto",
    "platformName": "iOS",
    "appium:app": "/Users/user/apps/7Mind_2.27.0.ipa",
    "appium:automationName": "XCUITest",
    "appium:deviceName": "iPhone",
    "appium:updatedWDABundleId": "de.benjamin-altpeter.WebDriverAgentRunner"
  }
  ```

  Replace `appium:app` with the path to any IPA, `appium:updatedWDABundleId` with the ID chosen in the previous step, and `appium:xcodeOrgId` with the personal team ID. To find that, open the *Keychain Access* app. On the left, select *login* under *Default Keychains*, then choose *My Certificates* in the top bar. Doubleclick the correct certificate. The ID is listed under *Organizational Unit*.
6. Use the latter two values for running the analysis.

## Setup

### Preparation on macOS

On macOS, we need to compile the Node bindings for Frida ourselves.

* Use Node 14.
* Clone https://github.com/frida/frida.
* Follow the steps "1.1. Create a certificate in the System Keychain -> 1.1.2. Manual steps" and "1.2. Trust the certificate for code signing -> 1.2.2. Manual steps" in https://sourceware.org/gdb/wiki/PermissionsDarwin but name the certificate `frida-cert`.
* Run:
  
  ```sh
  cd frida
  export MACOS_CERTID=frida-cert
  export IOS_CERTID=frida-cert
  sudo killall taskgated
  make node-macos NODE=/opt/homebrew/opt/node@14/bin/node # Replace with the path to your Node 14 if necessary.
  cd ..
  ```

  You will need to enter your credentials a lot of times.
* Clone https://github.com/frida/frida-node.
* Run:

  ```sh
  cd frida-node
  FRIDA=/Users/user/coding/frida npm install # Replace the path to the main frida repo if necessary.
  yarn link
  ```
* Run `brew install postgresql` to be able to install `psycopg2` later (https://github.com/psycopg/psycopg2/issues/1286#issuecomment-914286206).
* Install `libimobiledevice`: `brew install libimobiledevice ideviceinstaller`
* Install `sshpass`: `brew install esolitos/ipa/sshpass`
* SSH into the iDevice manually once to add it to the list of known hosts.

### Steps for all systems

```sh
npm install -g appium appium-doctor
# Run `appium-doctor --android` or `appium-doctor --ios` and resolve the issues.

git clone <clone_url>
cd <clone_dir>
yarn link frida # Only on macOS.
yarn

python3 -m venv venv
source venv/bin/activate
pip install mitmproxy frida-tools objection python-dotenv psycopg2-binary

cd src
cp .env.sample .env
nano .env
```

## Device preparation

### iOS

* Jailbreak
* Enable SSH server.
    * Install packages OpenSSH, Open, Sqlite3 from Cydia.
    * Connect using `root@<ip>`, password `alpine`.
* Settings
    * General
        * Background App Refresh: off (to hopefully minimize background network traffic)
        * Software Update
            * Automatic Updates
                * Install iOS Updates: off
                * Download iOS Updates: off
    * Display & Brightness
        * Auto-Lock: never
    * Privacy
        * Location Services
            * Location Services: on
        * Analytics & Improvements
            * Share iPhone Analytics: off
        * Apple Advertising
            * Personalised Ads: on (default)
    * App Store
        * Automatic Downloads
            * Apps: off
            * App Updates: off
* Install [Activator](https://cydia.saurik.com/package/libactivator/).
* Setup mitmproxy: https://www.andyibanez.com/posts/intercepting-network-mitmproxy/#physical-ios-devices
* Install [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2) (https://steipete.com/posts/jailbreaking-for-ios-developers/#ssl-kill-switch)
    * Install Debian Packager, Cydia Substrate, PreferenceLoader, PullToRespring, and Filza from Cydia.
    * Download latest release: https://github.com/nabla-c0d3/ssl-kill-switch2/releases
    * In Filza, go to `/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/Downloads` and install.
    * Respring by opening Settings and pulling down.
    * Enable in Settings under SSL Kill Switch 2.
* Install Frida: https://frida.re/docs/ios/#with-jailbreak
* Uninstall all third-party apps that are not absolutely necessary.
* Turn on Bluetooth.

## Mobile CMPs

* IAB TCF
    * Has mobile version: <https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/Mobile In-App Consent APIs v1.0 Final.md>
        * ~~Unclear: Relationship with TCFv2. Does that replace the mobile one as well? Seems to be obsolete (https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/pull/302)?~~
        * Superseded by: <https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/TCFv2/IAB%20Tech%20Lab%20-%20CMP%20API%20v2.md#in-app-details> (no important changes)
    * CMP data can be accessed via `NSUserDefaults` on iOS or `SharedPreferences` on Android (https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/Mobile%20In-App%20Consent%20APIs%20v1.0%20Final.md#how-do-third-party-sdks-vendors-access-the-consent-information-)
        * Docs by Usercentrics: https://docs.usercentrics.com/cmp_in_app_sdk/latest/apply_consent/apply-iab-consent/
        * Frida:
          ```js
          // See: https://stackoverflow.com/a/54818023, https://github.com/frida/frida/issues/488#issuecomment-490163530
          app_ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
          pref_mgr = Java.use('android.preference.PreferenceManager').getDefaultSharedPreferences(app_ctx);

          function dumpHashmap(hashmap, key_filter = false) {
              var HashMapNode = Java.use('java.util.HashMap$Node');
  
              var iterator = hashmap.entrySet().iterator();
              while (iterator.hasNext()) {
                  var entry = Java.cast(iterator.next(), HashMapNode);
                  if(!key_filter || entry.getKey().toString().toLowerCase().startsWith(key_filter.toLowerCase())) {
                      console.log(entry.getKey());
                      console.log(entry.getValue());
                      console.log();
                  }
              }
          }
          dumpHashmap(pref_mgr.getAll(), "iab");
          dumpHashmap(pref_mgr.getAll(), "gdpr");
          ```
  
          yields (for eBay Kleinanzeigen):
  
          ```
          iabtcf_UseNonStandardStacks
          0
  
          iabtcf_gdprApplies
          1
  
          iabtcf_SpecialFeaturesOptIns
  
  
          iabtcf_VendorLegitimateInterests
  
  
          iabtcf_PurposeOneTreatment
          0
  
          iabtcf_PurposeConsents
          1111111111
  
          iabtcf_PurposeLegitimateInterests
  
  
          IABTCF_AddtlConsent
          1~39.43.46.55.61.66.70.83.89.93.108.117.122.124.131.135.136.143.144.147.149.159.162.167.171.192.196.202.211.218.228.230.239.241.253.259.266.272.286.291.311.317.322.323.326.327.338.367.371.385.389.394.397.407.413.415.424.430.436.440.445.448.449.453.482.486.491.494.495.501.503.505.522.523.540.550.559.560.568.574.576.584.587.591.733.737.745.780.787.802.803.817.820.821.829.839.853.864.867.874.899.904.922.931.938.979.981.985.1003.1024.1027.1031.1033.1034.1040.1046.1051.1053.1067.1085.1092.1095.1097.1099.1107.1127.1135.1143.1149.1152.1162.1166.1186.1188.1192.1201.1204.1205.1211.1215.1226.1227.1230.1252.1268.1270.1276.1284.1286.1290.1301.1307.1312.1329.1345.1356.1364.1365.1375.1403.1411.1415.1416.1419.1440.1442.1449.1455.1456.1465.1495.1512.1516.1525.1540.1548.1555.1558.1564.1570.1577.1579.1583.1584.1591.1603.1616.1638.1651.1653.1665.1667.1671.1677.1678.1682.1697.1699.1703.1712.1716.1721.1722.1725.1732.1745.1750.1753.1765.1769.1782.1786.1800.1808.1810.1825.1827.1832.1837.1838.1840.1842.1843.1845.1859.1866.1870.1878.1880.1889.1899.1917.1929.1942.1944.1962.1963.1964.1967.1968.1969.1978.2003.2007.2027.2035.2039.2044.2046.2047.2052.2056.2064.2068.2070.2072.2074.2088.2090.2103.2107.2109.2115.2124.2130.2133.2137.2140.2145.2147.2150.2156.2166.2177.2179.2183.2186.2202.2205.2216.2219.2220.2222.2225.2234.2253.2264.2279.2282.2292.2299.2305.2309.2312.2316.2325.2328.2331.2334.2335.2336.2337.2343.2354.2357.2358.2359.2366.2370.2376.2377.2387.2392.2394.2400.2403.2405.2407.2411.2414.2416.2418.2422.2425.2427.2440.2447.2459.2461.2462.2468.2472.2477.2481.2484.2486.2488.2492.2493.2496.2497.2498.2499.2501.2510.2511.2517.2526.2527.2532.2534.2535.2542.2544.2552.2563.2564.2567.2568.2569.2571.2572.2575.2577.2583.2584.2589.2595.2596.2601.2604.2605.2608.2609.2610.2612.2614.2621.2628.2629.2633.2634.2636.2642.2643.2645.2646.2647.2650.2651.2652.2656.2657.2658.2660.2661.2669.2670.2673.2677.2681.2684.2686.2687.2690.2691.2695.2698.2707.2713.2714.2729.2739.2767.2768.2770.2771.2772.2784.2787.2791.2792.2798.2801.2805.2812.2813.2816.2817.2818.2821.2822.2827.2830.2831.2834.2836.2838.2839.2840.2844.2846.2847.2849.2850.2851.2852.2854.2856.2860.2862.2863.2865.2867.2869.2873.2874.2875.2876.2878.2879.2880.2881.2882.2883.2884.2885.2886.2887.2888.2889.2891.2893.2894.2895.2897.2898.2900.2901.2908.2909.2911.2912.2913.2914.2916.2917.2918.2919.2920.2922.2923.2924.2927.2929.2930.2931.2933.2939.2940.2941.2942.2947.2949.2950.2956.2961.2962.2963.2964.2965.2966.2968.2970.2973.2974.2975.2979.2980.2981.2983.2985.2986.2987.2991.2993.2994.2995.2997.3000.3002.3003.3005.3008.3009.3010.3011.3012.3016.3017.3018.3019.3024.3025.3034.3037.3038.3043.3044.3045.3048.3052.3053.3055.3058.3059.3063.3065.3066.3068.3070.3072.3073.3074.3075.3076.3077.3078.3089.3090.3093.3094.3095.3097.3099.3100.3104.3106.3109.3111.3112.3116.3117.3118.3119.3120.3121.3124.3126.3127.3128.3130.3135.3136.3139.3145.3149.3150.3151.3154.3155.3159.3162.3163.3167.3172.3173.3180.3182.3183.3184.3185.3187.3188.3189.3190.3193.3194.3196.3197.3209.3210.3211.3214.3215.3217.3219.3222.3223.3226.3227.3228.3230.3232.3234.3236.3237.3238
  
          iabtcf_VendorConsents
          11010111111111110101111111111111110110111101111111111001111111101111111110111111011111111111111011011101000111100110001101010111111111011111111110111111111011111111101101001100111000111000010111110111011011011111101111000011011101100111111111110101111111110010111111000101111111111101100011001110111011110001011101111110101010011010111110000010101011100100011110001001001011101101110110110000010010000100000111011011010001110011101001110111000100110101001001101100011110101010001001010101011010111100110011111011000110111001001101100111001010111110110011010010100010011110110011111001001001101001111011000110110111101101100111010110000001100001111111011111111001111111011101110100111111110110010010100110011110111111111111111111111111111111111111111110111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111101111111111111111111111111111111111011111111111111111111111111111111111111111111111111111111111111111111111111111011111111111111111111111111111111111111111111111111
  
          IABTCF_CmpSdkID
          309
  
          IABTCF_CmpSdkVersion
          2
  
          iabtcf_PublisherCustomPurposesConsents
          011
  
          iabtcf_PublisherCC
          DE
  
          iabtcf_PublisherLegitimateInterests
  
  
          iabtcf_PublisherConsent
  
  
          IABTCF_TCString
          b
  
          iabtcf_PublisherCustomPurposesLegitimateInterests
  
  
          iabtcf_PolicyVersion
          2
  
  
          GDPR2_CONSENT_FACEBOOK_PURPOSE_STATE
          1
  
          GDPR2_CONSENT_DFP_CONSENT
          full2-exp
  
          GDPR2_CONSENT_GOOGLE_AD_PURPOSE_STATE
          1
  
          GDPR2_VENDOR_LIST_VERSION
          116
  
          GDPR2_LAST_BANNER_DISPLAY_TIME
          1637680357379
  
          GDPR2_CUSTOM_VERSION
          2
  
          GDPR2_CONSENT_ADJUST_PURPOSE_STATE
          1
          ```
        * Editing prefs using Frida: `pref_mgr.edit().put<Type>(key, value).commit()`
        * For iOS:  
          ```js
          // Taken from: https://codeshare.frida.re/@dki/ios-app-info/
          function dictFromNSDictionary(nsDict) {
              var jsDict = {};
              var keys = nsDict.allKeys();
              var count = keys.count();
              for (var i = 0; i < count; i++) {
                  var key = keys.objectAtIndex_(i);
                  var value = nsDict.objectForKey_(key);
                  jsDict[key.toString()] = value.toString();
              }
          
              return jsDict;
          }

          prefs = ObjC.classes.NSUserDefaults.alloc().init().dictionaryRepresentation();
          dictFromNSDictionary(prefs);

          // TODO: The below should work but crashes as `ObjC.classes.NSJSONSerialization.isValidJSONObject_(prefs)` is `false`.
          err = ptr(ObjC.classes.NSError.alloc());
          jsons = ObjC.classes.NSJSONSerialization.dataWithJSONObject_options_error_(prefs, 1, err);
          json = ObjC.classes.NSString.alloc().initWithData_encoding_(jsons, 4).toString();
          ```
    * List of certified vendors: https://iabeurope.eu/cmp-list/
    * JSON list of vendors and purposes: https://vendor-list.consensu.org/v2/vendor-list.json

## Observations

* Few apps start with consent dialog, often some other wizardy UI (e.g. country selection) first.
* The consent dialog elements tend to have very descriptive IDs (like `de.zalando.prive:id/consent_button_accept_all`, `com.indeed.android.jobsearch:id/regPromoFooterPrivacyPolicy`, `com.ebay.kleinanzeigen:id/gdpr_consent_accept`) but not always (like `com.zhiliao.musically.livewallpaper:id/content_tv`).
* Some consent dialogs are in webviews.
* Some apps require login before any other interaction can be done. What to do here?
* Some tracking frameworks leave traces in prefs as well (e.g. `com.facebook.appevents.sessionStartTime`)

* App -> CMP/consent storage
    * Blablacar: Didomi (not compliant with TCF?!)
    * Cdiscount: TCF
    * Disneyland: Doesn't seem to save choices in prefs.
    * Doctolib: not in prefs
    * HP Smart: Manual storage (`allow_tracking: true`, etc.)
    * Lidl Plus: not in prefs
    * McDo: TCF, Didomi
    * Shein: TCF but `IABTCF_gdprApplies: 0`
    * TikTok Wall Picture: not in prefs
    * Zalando privé: not in prefs

* `IABUSPrivacy_String` is used by some US apps (https://developers.google.com/admob/android/ccpa).

* Very basic analysis of ~800 Android apps
    * 181/823 (22%) apps have any reference at all to privacy on the screen after 5s.
    * For 744/823 apps (90%), reading the prefs succeeded, 377/823 (46%) apps have non-empty prefs after running for 5s without any input.
    * 21/823 apps (3%) have privacy-related prefs without any user input.

## Detecting CMPs statically

* Exodus does `dexdump my.apk | grep "Class descriptor" | sort | uniq` to statically list class (and thus libraries) in an APK ([1](https://exodus-privacy.eu.org/en/post/exodus_static_analysis/)).
    * Can find things like `com/iabtcf` or `io/didomi`.
    * Of 3270 apps, 38 use `com.iabtcf`, 221 use class matching `/appconsent|BEDROCK|CommandersAct|consentdesk|consentmanager|didomi|Easybrain|FundingChoices|iubenda|madvertise|next14|ogury|onetrust|sibboventures|sourcepoint|uniconsent|TXGroup|usercentrics/i`.
    * Seems to only be detectable in rather small subset of apps => motivation for dynamic analysis.
* No prior art on iOS (that I found, anyway…) but can use `otool -L <binary_file_in_ipa>` to list shared libraries and `nm <binary_file_in_ipa>` or `symbols -w -noSources <binary_file_in_ipa>` to list symbol table (see https://stackoverflow.com/a/39668318, https://stackoverflow.com/a/32053076).
    * Neither of those works on Linux. [jtool2](http://newosxbook.com/tools/jtool.html) is an alternative that sometimes crashes, though.
    * For our purposes, this can easily be replicated on Linux: The only `otool` lines we are interested in, are the ones starting with `@rpath` (like `@rpath/AdjustSdk.framework/AdjustSdk`), the other ones (like `/usr/lib/swift/libswiftos.dylib`) are system libs.
    * The former seem to be a subset of the directories in `Payload/<app_name>.app/Frameworks` in the IPA.
    * Results (for old dataset from proj-ios): `with iabtcf: 0, with any cerifified CMP: 28, total: 1001`

## Criteria for compliant consent dialogs

* Limited to EU and German sources of law.

### Legal framework

* Art. 5(3) ePD delegates to Directive 95/46/EC (superseded by GDPR)
* BDSG only talks about consent in the context of law enforcement and is thus not relevant here.
* § 25(1) TTDSG delegates directly to the GDPR.

* guidelines: (Art. 4(11) GDPR)
    * freely given
    * specific
        * When the processing has multiple purposes, consent should be given for all of them. (Recital 32 GDPR)
    * informed
        * For consent to be informed, the data subject should be aware at least of the identity of the controller and the purposes of the processing for which the personal data are intended. (Recital 42 GDPR)
        * clear and comprehensive information […], inter alia, about the purposes of the processing (Art. 5(3) ePD)
    * unambiguous
    * statement or clear affirmative action
        * "This could include ticking a box when visiting an internet website, choosing technical settings for information society services or another statement or conduct which clearly indicates in this context the data subject’s acceptance of the proposed processing of his or her personal data." (Recital 32 GDPR)
        * Silence, pre-ticked boxes or inactivity are not consent (Recital 32 GDPR)
* controller needs to be able to demonstrate user has given consent (Art. 7(1) GDPR)
* in the case of written declaration which also concerns other matters (like TOS): (Art. 7(2) GDPR)
    * clearly distinguishable from the other matters
    * intelligible and easily accessible form
    * using clear and plain language
* right to withdraw consent at any time (Art. 7(3) GDPR)
* Prior to giving consent, the data subject shall be informed thereof. (Art. 7(3) GDPR)
* It shall be as easy to withdraw as to give consent. (Art. 7(3) GDPR)
* not freely given if performance of contract/provision of service is conditional on consent that is not necessary for the performance thereof (Art. 7(4) GDPR)
    * Consent should not be regarded as freely given if the data subject has no genuine or free choice or is unable to refuse or withdraw consent without detriment. (Recital 42 GDPR)
    * Consent is presumed not to be freely given if it does not allow separate consent to be given to different personal data processing operations despite it being appropriate in the individual case, or if the performance of a contract, including the provision of a service, is dependent on the consent despite such consent not being necessary for such performance. (Recital 43 GDPR)
* If the data subject’s consent is to be given following a request by electronic means, the request must be clear, concise and not unnecessarily disruptive to the use of the service for which it is provided. (Recital 32 GDPR)
* Cookies that need consent may only be set _after_ consent has been given (Art. 6(1) GDPR).

* TODO: Explicit consent for special categories (Art. 9 GDPR), third-country transfer without adequacy decision (Art. 49 GDPR)

### DPA recommendations

* Active action is necessary, preticked boxes or mere use of app don't constitute consent
    * https://www.datenschutzkonferenz-online.de/media/kp/dsk_kpnr_20.pdf
    * https://edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_202005_consent_en.pdf, 86.
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, A.4.2
* Consent has to be voluntary, i.e. it needs to be possible to use app without consenting
    * https://www.datenschutzkonferenz-online.de/media/kp/dsk_kpnr_20.pdf
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, A.4.2
* Notice has to inform about the possibility to withdraw consent at any time without detriment
    * https://www.datenschutzkonferenz-online.de/media/kp/dsk_kpnr_20.pdf
    * https://edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_202005_consent_en.pdf, 64.
    * https://www.baden-wuerttemberg.datenschutz.de/zum-einsatz-von-cookies-und-cookie-bannern-was-gilt-es-bei-einwilligungen-zu-tun-eugh-urteil-planet49/
    * https://www.ldi.nrw.de/mainmenu_Datenschutz/Inhalt/FAQ/EinwilligungDaten.php
    * https://lfd.niedersachsen.de/download/161158
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, A.4.3
* A consent banner that only mentions cookies can only receive consent under the ePD, not the GDPR
    * https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 9
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, B.1.3.5.1
* Necessary information: controller, purpose of access, cookie duration, access for third parties?
    * https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 12
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, A.4.2
* "Okay" is not consent
    * https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 14
    * https://lfd.niedersachsen.de/download/161158
    * https://www.baden-wuerttemberg.datenschutz.de/wp-content/uploads/2021/10/OH-int-Datentransfer.pdf, B.1.3.12.1
* Even "Agree" is not consent if details are hidden behind another link
    * https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 14
    * https://lfd.niedersachsen.de/download/161158
* Refusing consent has to be possible through inaction or with the same number of clicks as consenting
    * https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 14
    * https://www.lda.bayern.de/media/pm/pm2021_06.pdf
    * https://lfd.niedersachsen.de/download/161158
    * https://edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_202005_consent_en.pdf, 114.
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, A.4.3
* Concrete purposes need to be listed, "to improve user experience" is not sufficient
    * https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 16
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, A.4.2
    * https://lfd.niedersachsen.de/download/161158
* It needs to be possible to only consent to (adequate) subpurposes and/or recipients
    * https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 16
    * https://edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_202005_consent_en.pdf, 42.
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, A.4.2
* The "consent" button cannot be highlighted compared to the "refuse" button
    * https://www.lda.bayern.de/media/pm/pm2021_06.pdf
    * https://lfd.niedersachsen.de/startseite/infothek/faqs_zur_ds_gvo/faq-telekommunikations-telemediendatenschutz-gesetz-ttdsg-206449.html#10._Welche_Anforderungen_werden_an_die_Einwilligung_gemaess_25_Abs._1_TTDSG_gestellt_die_grundsaetzlich_beim_Einsatz_von_Cookies_und_bei_der_Einbindung_von_Drittdiensten_einzuholen_ist_
    * https://lfd.niedersachsen.de/download/161158
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, A.4.3
* Consent dialog may not make it impossible to access other required legal notices
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, A.4.1
* No purposes may be pre-selected
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, A.4.2
* Third-party recipients have to be mentioned explicitly
    * https://lfd.niedersachsen.de/download/161158
    * https://www.baden-wuerttemberg.datenschutz.de/wp-content/uploads/2021/10/OH-int-Datentransfer.pdf, A.4.2
* "Accept all" may not toggle additional, previously unselected, purposes
    * https://lfd.niedersachsen.de/download/161158
* Clear heading (no "we respect your privacy" but rather "data disclosure to third-parties for tracking purposes")
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, B.1.3.7 (includes list!)
* Consent notice must be in the language of the country it addresses
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, B.1.3.1
* Consent notice cannot be overly long or complex
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, B.1.3.3.3, B.1.3.3.4
* Consent notice saves consent but not refusal thereof and is thus displayed over and over again
    * https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, B.2.2.3

### What can be checked automatically?

* [W] Processing that needs consent (active action) may only be performed after it was given.
* [x] Unambiguous "agree" button (not "okay").
* [x] Refusing consent takes the same number of clicks as giving it or no action at all.
* [x] "Consent" button is not highlighted compared to "refuse" button.
* [x] Using app needs to be possible after refusing/withdrawing consent.
* [ ] Consent notice includes at least the identity of the controller, the concrete purposes, storage duration, access for third parties (explicitly listed).
* [ ] Consent notice informs of right to withdrawal.
* [ ] Details may not be hidden after another link if consenting is possible on that screen.
* [ ] Giving consent for subpurposes is possible.
* [ ] No purposes are pre-selected.
* [ ] "Accept all" may not toggle additional, previously unselected, purposes.

## Detecting CMPs automatically

* Existing research for the web
    * Many purely manual approaches (https://www.researchgate.net/publication/332888923_4_Years_of_EU_Cookie_Law_Results_and_Lessons_Learned, https://sci-hub.se/https://dl.acm.org/doi/abs/10.1145/3321705.3329806, https://www.researchgate.net/profile/Martin-Degeling/publication/334965379_Uninformed_Consent_Studying_GDPR_Consent_Notices_in_the_Field/links/5d638e6c458515d610253bb1/Uninformed-Consent-Studying-GDPR-Consent-Notices-in-the-Field.pdf)
    * Some with CMP-specific adapters: https://sci-hub.se/https://dl.acm.org/doi/abs/10.1145/3442381.3450056
        * Uses: https://github.com/cavi-au/Consent-O-Matic
    * Via TCF: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9152617
    * Noyb (https://noyb.eu/en/noyb-aims-end-cookie-banner-terror-and-issues-more-500-gdpr-complaints) don't explain their approach but based on available details (esp. https://wecomply.noyb.eu/en/app/faq#how-can-i-make-my-banner-compliant) likely use CMP-specific adapters, maybe in combination with TCF.
    * Privacy policy detection tends to be keyword-based: https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-2_Degeling_paper.pdf, https://dl.acm.org/doi/pdf/10.1145/3178876.3186087
        * Keyword list: https://github.com/RUB-SysSec/we-value-your-privacy/blob/master/privacy_wording.json
    * https://www.open.ou.nl/hjo/supervision/2021-koen-aerts-msc-thesis.pdf and https://pure.tudelft.nl/ws/files/57080768/vaneijk_conpro19.pdf rely on adblock filter lists (like https://secure.fanboy.co.nz/fanboy-cookiemonster.txt), which are _very_ broad, e.g. detecting any element with `CNIL` or `Cookie` in its ID. Manual check revealed error margin of ~15%, interestingly skewed towards false-negatives.
* Idea: Use similar approach based on element names (maybe also include text?) but define more stringent requirements, e.g. to have button that looks like "Accept" in the same hierarchy.
* Idea: Image-based?
* Quick test: Run adblock lists on Android.

* Observations
    * Games tend to not be machine-readable (`android.view.View` that Appium can't look inside). Some apps also have machine-readable and non-machine-readable elements (e.g. Glitter Live). -.-
    * In quite a few apps, the privacy notice is in an element that is called `terms` or `eula`, which means we cannot distinguish this from actual TOS by the ID. Sometimes, that is even the heading and it is only possible from reading the text (if that!) to recognize the notice as privacy-related (e.g. `com.fast.free.unblock.secure.vpn`).
    * The line between a consent notice and dialog is fairly blurry (e.g. Flightradar, Pinterest). I have used to following distinction: A dialog prompts an interaction from the user (a button, checkbox, etc., though pre-checked boxes are also included), while a notice is only informational. The interaction needs to be specifically privacy-related. A notice that is included in a sign-up form for example would not count as a dialog.
    * Descriptive IDs (or any IDs at all) are not that common. We really need to do text-based matching.
* Ideas
    * To be a dialog, app needs to match `dialog`, at least one `button` and at least one `keyword`. To be notice, app has to match `notice` and at least one `keyword`.
    * Check for dialog first. If app doesn't meet conditions, check for notice. Finally, check for link. The additional `keyword` matching is necessary to weed out the odd TOS only dialog/notice.
    * We use different "classes" of keywords, where e.g. `store cookies` yields one point but `European Court of Justice` only yields half a point, and then require some score.
    * TODO: Maybe it really isn't such a good idea to distinguish between notice and dialog. I genuinely often struggle to do this manually even.
        * -> We do still distinguish but only by whether there is a button. The other criteria are identical for dialogs and notices.
    * Include IAB labels?
    * [x] Problem with webviews. Only have correct element data on the second try?! (e.g. "Lecker") The first `findElements()` call doesn't find 
* Cases where I'm unclear:
    * Lomeda ("Dating App"): Text is split across multiple elements, so not detected. Appium doesn't seem to have an `innerText()`-type function. Manually concat all child texts? But then we could also just use the root element, couldn't we?
    * Should we distinguish between dialog and notice texts? Would it not be smarter to just use the button as the distinguishing feature?
        * -> Yes, we do that now.
    * For Pinterest case: Require that the dialog text comes _before_ the button?
        * -> No, there are other cases where this would lead to a false-negative.

* Notes from meeting
    * For the concat thing: Maybe move up divs and calculate keywords/text, repeat until that doesn't go up anymore (smart ascent). But only if necessary, ok to leave those cases out.
    * To find href, an idea might be: Statically grep app for button ID? Might not work/be worth it, though.
    * For the warnings before the complaints: Include a questionaire? (IRB approval?)
        * -> No warnings and complaints. Only privately.
    * Document how free Apple dev cert works (with Appium)

## IAB TCF decision (https://www.iccl.ie/news/gdpr-enforcer-rules-that-iab-europes-consent-popups-are-unlawful/)

* Broad definition of "personal data":
    * identifi_able_: "As soon as a CMP stores or reads the TC String on a user's device using a euconsent-v2 cookie, [it] can be linked to the IP address of the user's device. In other words, CMPs have the technical means to collect IP addresses (as indicated in their pop-up) and to combine all information relating to an identifiable person. The possibility of combining the TC String and the IP address means that this is information about an identifiable user." (para. 304)
    * PD assumed as purpose is explicitly to single out person: "In other words, if the purpose of the processing is the singling out of persons, it may be assumed that the controller or another party has or will have at their disposal the means by which the data subject may reasonably be expected to be identified" (para. 310)
* Broad definition of "controller":
    * Processing of data not necessary: "It is therefore clear to the Litigation Chamber that the defendant does not necessarily have to process the personal data concerned itself, nor does it have to be able to grant itself any access to the personal data, in order for IAB Europe to be considered a data controller, as in relation to a framework for which the defendant moreover charges an annual fee of 1.200 EUR to participating organisations." (para. 328)
    * Impact on others' processing:
        * "If it appears that an organisation plays a decisive role in the dissemination of  personal data or that the processing operations carried out under the influence of the organisation may substantially affect the fundamental rights to privacy and to the  protection of personal data, that organisation should be regarded as a data controller." (para. 329)
        * "CMPs are obliged to register with IAB Europe in order to be able to generate a TC String and must follow the technical specifications developed by IAB Europe in cooperation with IAB Tech Lab regarding the API with which CMPs can generate the TC String and adtech vendors and publishers can read it." (para. 344)
* Legal basis for TC string processing: only legitimate interest potentially applicable (para. 409)
    * Balance between interests not met due to no opt-out (para. 421) and lack of information (para. 422).

* TCF doesn't capture valid consent for OpenRTB
    * not informed:
        * Purposes "Measure content performance" and "Apply market research to generate audience insights" not sufficiently clearly described (para. 433)
        * No overview of categories of data collected in CMP interfaces (para. 434)
        * "the recipients for whom consent is obtained are so numerous that users would need a disproportionate amount of time to read [information about the identity of all controllers], which means that their consent can rarely be sufficiently informed." (para. 435)
        * information "too general to reflect the specific processing operations of each vendor" (para. 436)
        * enrichment of data in bid requests but orgs cannot indicate what data they already hold => not informed (para. 437)
    * consent cannot be withdrawn as easily as given (para. 438)
* OpenRTB processing via TCF cannot rely on legitimate interest
    * no explanation of legitimate interests pursued (para. 448)
    * no measures for data minimisation => necessity bar not met (para. 455, 456) (does not apply to TCF itself, para. 497)
    * users cannot expect processing due to large number of TCF partners (para. 459)
    * EDPB: legitimate interest not valid for direct markting involving behavioural advertising (para. 460)
* OpenRTB processing via TCF cannot rely on contractual necessity
    * EDPB: (pre)contractual necessity of the processing is not a legal ground applicable to behavioural advertising (para. 462)
    * lit. b not mentioned anywhere as possible legal basis (para. 463)
* Transparency requirements not met (para. 467)
    * IAB Europe can claim "records of consent" from CMP but doesn't inform data subjects of that (para. 468)
    * information fatigue, surprises after consent (para. 469)
    * users cannot identify "the processing purposes associated with the authorisation of a particular vendor or which adtech vendors will process their data for a specific purpose" (para. 471)
    * large number of third parties fundamentally incompatible with sufficiently informed consent (para. 472)
* Lack of appropriate measures on behalf of IAB Europe
    * IAB Europe forsees possible falsification of TC strings (para. 485, 486)
    * Compliance programs not sufficient, no dissuasive measures (para. 488)
    * TC string has no measures for transfering data outside the EU (para. 491)

## Tracking request adapters

* Endpoints to consider (some of these will be hard to reverse engineer; went through all with at least 15/1326 apps):
    * [x] https://www.facebook.com/adnw_sync2
    * [x] https://graph.facebook.com/network_ads_common

    * [ ] https://app-measurement.com/a (make sure app ID matches!)
    * [ ] https://firebaselogging-pa.googleapis.com/v1/firelog/legacy/batchlog
    * [ ] https://csi.gstatic.com/csi
    * [ ] https://ssl.google-analytics.com/batch
    * [ ] https://rr1---sn-4g5lzney.googlevideo.com/videoplayback
    * [ ] https://rr1---sn-4g5ednse.googlevideo.com/videoplayback
    * [ ] https://rr5---sn-4g5e6nzs.googlevideo.com/videoplayback
    * [ ] https://rr3---sn-4g5e6nzz.googlevideo.com/videoplayback
    * [ ] https://play.googleapis.com/log/batch

    * [ ] https://auiopt.unityads.unity3d.com/v1/category/experiment
    * [x] https://publisher-config.unityads.unity3d.com/games/3268074/configuration
    * [x] https://auction.unityads.unity3d.com/v4/test/games/3268074/requests
    * [ ] https://config.uca.cloud.unity3d.com/
    * [ ] https://cdp.cloud.unity3d.com/v1/events
    * [ ] https://httpkafka.unityads.unity3d.com/v1/events
    * [ ] https://thind.unityads.unity3d.com/v1/events

    * [x] https://app.adjust.com/session
    * [x] https://app.adjust.com/attribution
    * [x] https://app.adjust.com/event

    * [ ] https://googleads.g.doubleclick.net/mads/gma
    * [ ] https://googleads.g.doubleclick.net/pagead/interaction/
    * [ ] https://googleads.g.doubleclick.net/xbbe/pixel
    * [ ] https://googleads.g.doubleclick.net/pagead/adview
    * [ ] https://pagead2.googleadservices.com/pagead/adview
    * [ ] https://googleads.g.doubleclick.net/dbm/ad
    * [ ] https://googleads.g.doubleclick.net/pagead/conversion/
    * [ ] https://googleads4.g.doubleclick.net/pcs/view
    * [ ] https://pagead2.googlesyndication.com/pagead/gen_204
    * [ ] https://pagead2.googlesyndication.com/pcs/activeview
    * [ ] https://bid.g.doubleclick.net/dbm/vast
    * [ ] https://www.googleadservices.com/pagead/aclk
    * [ ] https://pubads.g.doubleclick.net/gampad/ads
    * [ ] https://www.googleadservices.com/pagead/conversion/1001680686/

    * [ ] https://ms.applovin.com/5.0/i
    * [ ] https://d.applovin.com/2.0/device
    * [ ] https://rt.applovin.com/4.0/pix
    * [ ] https://ms.applovin.com/1.0/mediate
    * [ ] https://prod-ms.applovin.com/1.0/event/load

    * [x] https://in.appcenter.ms/logs
    * [ ] https://codepush.appcenter.ms/v0.1/public/codepush/report_status/deploy

    * [x] https://api.onesignal.com/players

    * [x] https://outcome-ssp.supersonicads.com/mediation

    * [x] https://adc3-launch.adcolony.com/v4/launch
    * [ ] https://events3alt.adcolony.com/t/5.0/session_start
    * [ ] https://events3.adcolony.com/t/5.0/install
    * [x] https://androidads4-6.adcolony.com/configure

    * [x] https://ads.mopub.com/m/open
    * [x] https://ads.mopub.com/m/gdpr_sync

    * [x] https://api2.branch.io/v1/install

    * [x] https://ads.api.vungle.com/config
    * [x] https://api.vungle.com/api/v5/ads
    * [x] https://events.api.vungle.com/api/v5/cache_bust
    * [x] https://api.vungle.com/api/v5/new

    * [ ] https://conversions.appsflyer.com/api/v6.3/androidevent
    * [ ] https://conversions.appsflyer.com/api/v6.2/androidevent
    * [ ] https://conversions.appsflyer.com/api/v6.4/androidevent
    * [ ] https://conversions.appsflyer.com/api/v5.4/androidevent
    * [ ] https://inapps.appsflyer.com/api/v6.3/androidevent

    * [ ] https://config.inmobi.com/config-server/v1/config/secure.cfg

    * [x] https://startup.mobile.yandex.net/analytics/startup
    * [x] https://report.appmetrica.yandex.net/report

    * [x] https://sessions.bugsnag.com/

    * [ ] https://data.flurry.com/v1/flr.do

    * [x] https://infoevent.startappservice.com/tracking/infoEvent
    * [x] https://infoevent.startappservice.com/infoevent/api/v1.0/info
    * [x] https://trackdownload.startappservice.com/trackdownload/api/1.0/trackdownload

    * [ ] https://api.segment.io/v1/import

    * [x] https://configure.rayjump.com/setting
    * [x] https://analytics.rayjump.com/

    * [ ] https://pangolin16.isnssdk.com/api/ad/union/sdk/settings/

    * [x] https://config.ioam.de/appcfg.php

    * [x] https://live.chartboost.com/api/install
    * [x] https://live.chartboost.com/api/config

    * [ ] https://dpm.demdex.net/id

    * [x] https://logs.ironsrc.mobi/logs

### SQL

To find interesting endpoints:

```sql
select
       count(1) c, count(distinct apps.name) app_count, r.method,
       regexp_replace(concat(r.scheme, '://', r.host, r.path), '\?.+$', '') u from apps
    join runs on apps.id = runs.app join requests r on runs.id = r.run
    where (r.method = 'POST' or r.path ~ '\?.{25,}')
    group by u, r.method order by app_count desc;
```

To view the corresponding requests:

```sql
select name, r.id, r.method, r.path, r.content, r.content_raw from apps
    join runs on apps.id = runs.app join requests r on runs.id = r.run
    where regexp_replace(concat(r.scheme, '://', r.host, r.path), '\?.+$', '')
        like '${url}'
    order by length(r.path) + length(r.content);
```

## Apps

### App selection

* iOS
    * The `https://itunes.apple.com/WebObjects/MZStore.woa/wa/topChartFragmentData?cc=de&genreId=6000&pageSize=100&popId=27&pageNumbers=0` endpoint now only returns 100 entries.
        * `popId` values (determined by trying all values between 0 and 100, and comparing with: https://appfigures.com/top-apps/ios-app-store/germany/iphone/top-overall)
            * `27`: top free iPhone
            * `30`: top paid iPhone
            * `38`: top grossing iPhone
            * `44`: top free iPad
            * `46`: top grossing iPad
            * `47`: top paid iPad
            * additional values that return something (unsure what): `79`, `80`, `88`, `89`, `90`, `96`, `97`, `98`, `99`, `100`
            * between `101` and `156`, most values also return something
            * starting from `157`, you get 500 errors
    * "RSS feeds" (https://rss.applemarketingtools.com/) have changed, can still get 200 apps but only for "top free" and "top paid" now
    * Older "RSS feed" API, 100 per genre (https://stackoverflow.com/a/52750825/3211062)
        * `https://itunes.apple.com/de/rss/<channel_name>/genre=<genre_id>/explicit=true/limit=100/json`
        * For getting the genres: https://itunes.apple.com/WebObjects/MZStoreServices.woa/ws/genres (https://web.archive.org/web/20190920135004/https://affiliate.itunes.apple.com/resources/documentation/genre-mapping/)
            * `36` is the top category for iOS apps
            * probably best to ignore third-level genres, as these are only for games and newsstand?
        * Valid channel names (not all listed in the genre list work): `topfreeapplications`, `topfreeipadapplications`, `toppaidipadapplications`, `topapplications`, `toppaidapplications`
    * `https://itunes.apple.com/WebObjects/MZStore.woa/wa/viewTop?cc=de&genreId=36&l=en&popId=27` (from iTunes)
        * up to 200 results (per category)
        * but for some reason `json.storePlatformData.lockup.results` only has 84 results with meta data
        * to access all IDs: `json.pageData.segmentedControl.segments[0].pageData.selectedChart.adamIds`

### Better method for aquiring IPAs

* [ipatool](https://github.com/majd/ipatool) seems promising, works for downloading already bought apps (on recent macOS) but cannot buy new apps
    * Replicating requests as defined in code and sending them manually doesn't work
    * To proxy macOS traffic through mitmproxy for inspection:
        * In network preferences, set HTTP and HTTPS proxy
        * Go to http://mitm.it and follow instructions for macOS
        * In Terminal:

          ```sh
          export http_proxy="http://<ip>:8080"
          export https_proxy="http://<ip>:8080"
          export all_proxy="http://<ip>:8080"
          ```
    * macOS pins certifications for certain domains, including apple.com. -.-
    * I've managed to disable cert pinning in code.
    * Nonetheless, even if I exactly replicate the request as seen by mitmproxy, I still get "The Apple ID you entered couldn’t be found or your password was incorrect. Please try again."
    * Even (naively) replicating the request through Swift on the M1 doesn't work.

    * I've gotten further trying to modify ipatool to use the 3u buy endpoint.
        * Making the requests through ipatool, I now finally actually get different responses from Apple!
        * One problem, though: ipatool identifies itself to the auth endpoint as Apple Configurator while 3u identifies itself as an old version of iTunes. The auth cookies from the two are unfortunately _not_ compatible. If I try to make a 3u buy request with the ipatool cookies, the API returns a prompt to login again.
        * However, if I grab the cookies from 3u and manually set them in ipatool, it does work (though the token seems to be very short-lived).
        * To use the 3u auth endpoint, you need an `X-Apple-ActionSignature` which I can't generate yet.
        * Breakthrough: Seems like you can just call the buy endpoint as Configurator. Apple won't return the download URL for that request but you can afterwards just call Configurator's download API!

## Complaints about illegal practices

* § 25 TTDSG (the German implementation of Art. 5(3) ePD) is very powerful and violations can easily be detected automatically. The regular German DPAs are responsible for enforcing it (§ 1(1)(8) TTDSG).

## TODO

* [x] Try Appium on Android.
* [x] Try Appium on iOS.
* [x] Start many apps and make screenshot for initial manual analysis.
* [x] Explore app frameworks/libraries to check for CMPs.
    * If we do find them, try to interact with them using Frida.
* [x] Find out how to get element style properties (to answer questions like "which button is more prominent?").
    * Not possible.
* [ ] Automate 3u with Frida?
* [ ] ~~Go through CMPs and check whether their state can be read programmatically/they can be interacted with programmatically.~~
* [x] Write adapters for different trackers and endpoints that detect their presence and can extract the transmitted data.
    * Will also be helpful for complaint generator.
    * Idea: While value matching works for data points we can control, this isn't possible for everything, e.g. OS (`android`, `ios`) or screen dimensions are way too generic to be matched that way.
* [x] After CMP detection: Do violation detection next, then interaction.
* [ ] Save raw mitmproxy flows/logs. (`--save_stream_file` but also save cmd logs)
* [ ] Look for SDK indicators in prefs?
* [x] Change geolocation.
* [ ] For button color highlight: Also compare with background.
* [ ] Cert pinning bypass
* [ ] Honey data
* [ ] Python `requirements.txt`
* [x] Verify app is still running after waiting.
* [ ] Look at cookies and headers.
    * Same cookie values across different apps?
    * Compare with cookie DB?
* [ ] Can we fix incorrect country detections (`US`)?
* [ ] Set device name.
* [ ] Record failures.
* [ ] For iOS:
    * [ ] There tend to be multiple nested elements with the same name/label that are displayed as a single element. This breaks the violation detection, which expects exactly one affirmative and negative button. While all of those elements are `visible`, it seems like only one of them is `accessible`.
    * [ ] We need to make sure to always dismiss all modals as they can stick around after the app is uninstalled and Appium will then only see them.
    * [x] We sometimes get into a state where Appium sees the system UI and detects a "No SIM" "button". It seems like this can be resolved by getting rid of all modals.
        * Maybe we should throw if we detect that?
    * [ ] Read IDFV using Frida and check for that.
* [ ] More potential violations to detect:
    * [ ] Consider US transfers without consent a violation, maybe go even deeper (scan consent notice for keywords)?
    * [ ] Check consent dialog language.
    * [ ] Check for "forbidden" heading (BaWü).
* Questions for Simon:
    * "the listed options (consent for which processing is requested?, which third-party tracking companies are used?) will be extracted" -> I can do that for the TCF apps, for everything else, this will be very difficult.
        * -> only for TCF apps
    * Interaction with CDs: Should I go further (would much likely mean manual interaction)?
        * Shouldn't be too time consuming considering how few dialogs there are.
        * Problem: What to check?

        * -> consider manual clicking but not necessary
    * No interaction with apps beyond consent dialog okay?
        * -> is okay as a limitation
    * How to cite laws?
        * -> ok as-is
    * For button highlight violation detection: What if there is more than one of each button?
        * For each positive button, go through all negative buttons and only note violation if it is highlighted compared to all of them?
            * -> do that

### Promises from proposal

* [x] Compile list of criteria for compliant consent dialogs, based on applicable legislation, court rulings, supervisory authority recommendations, and previous work.
* [x] Extend existing analysis framework to allow extraction of elements on screen and interaction with apps.
* [~] Extend existing analysis framework for better identification of tracking, based on looking at actual transmitted data.
* [~] Identify consent dialogs as well as their frameworks and settings in apps. Compare results with research for the web.
* [~] Identify violations in consent dialogs (dark patterns, nudging).
* [~] Interact with consent dialogs and measure effect of the choices on the tracking going on.
* [ ] Evaluate results and compare with privacy labels on iOS.
