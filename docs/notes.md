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

## Instrumentation

* Appium
    * iOS: XCUITest driver only runs on macOS, might (?) need paid developer account (http://appium.io/docs/en/drivers/ios-xcuitest-real-devices/, https://github.com/appium/appium-xcuitest-driver#requirements)
    * Android: Works just fine with the Emulator.
    * [Appium Inspector](https://github.com/appium/appium-inspector) very helpful for… inspecting apps and finding IDs, etc.
    * Might even be possible to use a real device cloud like BrowserStack.

## Mobile CMPs

* IAB TCF
    * Has mobile version: <https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/master/Mobile In-App Consent APIs v1.0 Final.md>
        * Unclear: Relationship with TCFv2. Does that replace the mobile one as well? Seems to be obsolete (https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/pull/302)?
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

## TODO

* [x] Try Appium on Android.
* [ ] Start many apps and make screenshot for initial manual analysis.
* [x] Explore app frameworks/libraries to check for CMPs.
    * If we do find them, try to interact with them using Frida.
* [ ] Find out how to get element style properties (to answer questions like "which button is more prominent?").
