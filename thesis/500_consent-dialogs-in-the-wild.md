# Consent Dialogs in the Wild

This chapter will explore how consent dialogs are actually implemented in the wild, both on the web and on mobile, to gain insights on which approach to use for the analysis in [@sec:analysis-method].

## Situation on the Web

* First look at the web, most prior research on that

### Consent Management Platforms

* Various companies offer so-called CMPs, TODO: define what that is.
* Means that individual websites don't have to implement CD themselves and also helps with legal compliance: CMP should make sure that actions that require consent (like setting certain cookies) are only done after consent has been given.
* Also conducive to research as one now only needs to handle a handful of CMPs instead of custom implementations on every website.

* TODO: Examples of configuring a CMP, websites can set various options, including ones that make the dialog non-compliant.

On the web, usage of CMPs is common. Recent research detected the use of CMPs on between 6&nbsp;% and 13&nbsp;% of European websites, depending on their Tranco rank [@hilsPrivacyPreferenceSignals2021; @matteCookieBannersRespect2020]. Ad tech companies Kevel reports the presence of a CMP on 44&nbsp;% of the top 10k US sites for Q1 2022 [@kevelConsentManagementPlatform2022].

### IAB Transparency & Consent Framework

* Websites often use third-party scripts from many different vendors for all kinds of purposes, including advertising and tracking. Many of them require consent (see [@sec:legal-background]).
* How does ensuring that those only start processing after consent has been given work? Without a common framework, either each CMP would have to implement custom handlers for each possible third-party script or each third-party script would need to know how to communicate with all possible CMPs.
* IAB Europe, an association that represents the interests of the digital advertising and marketing industry in Europe [@iabeuropeUs2021], maintains TCF standard, which defines common interface for CMPs and third-party scripts to communicate. Defines how websites should store consent and legitimate interest records, as well as conditions on how to prompt the user for consent and inform them through CDs. For that, maintain list of purposes and vendors the website can ask users to consent to.
* Timeline: "On 25 April 2018  the IAB Europe Transparency and Consent Framework (TCF) v1.1 was launched", "On 21 August 2019 a revised version of the TCF, TCF v2.0 was launched" (https://iabeurope.eu/transparency-consent-framework/). TODO: What about v1.0 (-> not public)?
* CMPs typically implement TCF [@onetrustOneTrustPreferenceChoiceCMP2022; @usercentricsgmbhTCFExplainedMost2020; @iubendas.r.lCompleteGuideIubenda2020; @cookiebotIABTransparencyConsent2022]

* Explain TCF
    * distinguishes: publisher (entity running the website), CMP (entity providing the CMP, can also be a publisher's in-house CMP if registered with IAB Europe), vendor (third-party embedded in publisher's website, e.g. ad or tracking provider)
    * Both CMPs and vendors need to register with IAB Europe, annual fee of 1,500 € [@iabeuropeJoinTCF2021]
    * Consent information is stored in TC string, which encodes^[IAB Europe offers a JavaScript library (<https://github.com/InteractiveAdvertisingBureau/iabtcf-es>) and an online tool (<https://iabtcf.com>) to decode and encode TC strings.] [@iabtechlabTransparencyConsentString2022]:
        * Metadata: TCF version, last update time
        * Consent records: per purpose and per vendor
        * Legitimate interest records: objections to them by the user^[The fact that the TCF allows a publisher to use a legitimate interest for a certain processing doesn't necessarily mean that this is legal [@mattePurposesIABEurope2020a]. TODO: Move somewhere else.]
        * Publisher restrictions: allow the publisher to specify custom requirements to restrict how vendors may process personal data
        * Publisher transparency and consent data: Allows the publisher to store consent and legitimate interest data for their own purposes
        * Jurisdiction data: country publisher is based in
    * TC strings may only be created or changed by CMP [@iabtechlabTransparencyConsentString2022], CMP is free to choose where to store TC string [@iabtechlabIABEuropeTransparency2021]
    * The CMP must expose the following API commands through a the `__tcfapi(command, version, callback, parameter)` function on the `window` object [@iabtechlabConsentManagementPlatform2021]:
        * `getTCData`: to receive an object with an object representing the parsed TC string
        * `ping`: to check whether the CMP has finished loading and whether it believes the GDPR applies in the context of this visit^[The TCF does not mandate how the CMP is supposed to determine whether the GPDR applies, it only mentions using the user's geolocation as one option. Vendors are required to adhere to the CMP's determination. [@iabtechlabConsentManagementPlatform2021] However, as explained in [@sec:bg-gdpr], the user's location alone is not necessarily sufficient for determining whether the GDPR applies.]
        * `addEventListener`: to register an event listener for (among other things) changes to the TC string
        * `removeEventListener`: to remove a registered event listener
    * If script wants to start processing, it [@iabtechlabConsentManagementPlatform2021]:
        1. Determine whether CMP is loaded on page by checking for the presence of the `__tcfapi()` function, otherwise assume no consent or legitimate interest. If the script is loaded in an iframe instead of directly on the page (common for ads), use `postMessage()` API
        2. Request the TC data through the `getTCData` command, check whether legal basis for processing is available. Only if so, start processing.
        3. Subscribe to change events through the `addEventListener` command, to notice if user withdrew consent for example and then stop processing accordingly

While not the TCF's intended purpose, the fact that the CMP data can be easily read programatically through the API that has to be provided, has also enabled research on consent dialogs on the web [@hilsPrivacyPreferenceSignals2021; @matteCookieBannersRespect2020; @aertsCookieDialogsTheir2021], and is even used by consumer protection organizations to automatically find violations in popular websites to pursue legal action against [@noyb.euNoybAimsEnd2021].

## Situation on Mobile

If the situation were similar on mobile and apps also commonly implemented the TCF or at least used a limited number of CMPs, this would make the desired analysis easy. This section will now look at whether that's the case. (TODO: This is terrible, reword!)

### Use of IAB TCF

Version 2.0 of the IAB TCF also supports CMPs in mobile apps on Android and iOS [@iabtechlabConsentManagementPlatform2021]. As native apps don't support running JavaScript code, a different API mechanism is used here. CMPs must instead store consent details (including the TC string) via the platform-specific per-app storage interfaces, namely `SharedPreferences` on Android and `NSUserDefaults` on iOS. Vendor SDKs can also access these stores to read the TCF data and set listeners to be informed of updates, thus the same steps as on the web can be used to determine whether an SDK can process the user's data on mobile, just with a slightly different implementation.

The TCF mandates the keys to be used for storing the consent details, most importantly [@iabtechlabConsentManagementPlatform2021]:

* `IABTCF_PolicyVersion`: The version of the TCF that is the basis for these properties.
* `IABTCF_gdprApplies`: The CMP's determination of whether the GDPR applies to the particular use of the app, same as on the web, with `0` meaning that the GDPR does not apply, `1` meaning that the GDPR does apply, and an unset value meaning that the CMP has not (yet) determined this.
* `IABTCF_TCString`: The TC string containing all consent information as explained in the previous section.
* Various other properties containing values already represented in the TC string but in parsed form to avoid SDKs needing to parse the string themselves.

For analysis purposes, it is necessary to read those properties from outside the app. That is possible, both for Android and iOS, using [Frida](https://frida.re/). Frida is a dynamic instrumentation toolkit for native apps that allows the user to inject JavaScript code into running applications and thus interact with native functions and runtime memory [@thefridacontributorsFridaDocs2022].

On Android, the `SharedPreferences` of an app can be accessed by injecting Frida and running the following script:

```js
var app_ctx =
    Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
var pref_mgr =
    Java.use('android.preference.PreferenceManager')
        .getDefaultSharedPreferences(app_ctx);
console.log(pref_mgr.getAll());
```

Similarly, on iOS the `NSUserDefaults` of a running app can be accessed using the following Frida script:

```js
var prefs = ObjC.classes.NSUserDefaults.alloc().init();
console.log(prefs.dictionaryRepresentation());
```

In both cases, for automated analysis, the objects would still need to be converted from their respective platform-native representation to JSON but that step is omitted here for brevity.

Unlike on the web, no prior research on how common TCF usage is on mobile exists as far as the author is aware. To gauge whether reading the TCF preferences is a viable approach for this thesis, a simple analysis was performed on a dataset of 823 popular Android apps from November 2021: The apps were run in an Emulator and left running for 5 seconds. Afterwards, a screenshot was taken and the `SharedPreferences` of the respective app were saved. Afterwards, the screenshots were manually looked at to determine whether the app showed any reference to data protection (like a consent dialog, a privacy notice, or even just a link to a privacy policy).

181 of the 823 (22&nbsp;%) apps displayed such a reference to data protection on screen after 5 seconds. However, only 21 of the 823 apps (3&nbsp;%) had set a corresponding privacy-related preference (i.e. one with a key that includes `IABTCF` or `GDPR`). This suggests that the IAB TCF is not commonly implemented on mobile.

### Use of CMPs

## Consequences for Analysis

<!--
* Situation on mobile
    * CMPs also rarely used
        * Exodus does `dexdump my.apk | grep "Class descriptor" | sort | uniq` to statically list class (and thus libraries) in an APK ([1](https://exodus-privacy.eu.org/en/post/exodus_static_analysis/)).
            * Can find things like `com/iabtcf` or `io/didomi`.
            * Of 3270 apps, 38 use `com.iabtcf`, 221 use class matching `/appconsent|BEDROCK|CommandersAct|consentdesk|consentmanager|didomi|Easybrain|FundingChoices|iubenda|madvertise|next14|ogury|onetrust|sibboventures|sourcepoint|uniconsent|TXGroup|usercentrics/i`.
            * Seems to only be detectable in rather small subset of apps => motivation for dynamic analysis.
        * No prior art on iOS (that I found, anyway…) but can use `otool -L <binary_file_in_ipa>` to list shared libraries and `nm <binary_file_in_ipa>` or `symbols -w -noSources <binary_file_in_ipa>` to list symbol table (see https://stackoverflow.com/a/39668318, https://stackoverflow.com/a/32053076).
            * Neither of those works on Linux. [jtool2](http://newosxbook.com/tools/jtool.html) is an alternative that sometimes crashes, though.
            * For our purposes, this can easily be replicated on Linux: The only `otool` lines we are interested in, are the ones starting with `@rpath` (like `@rpath/AdjustSdk.framework/AdjustSdk`), the other ones (like `/usr/lib/swift/libswiftos.dylib`) are system libs.
            * The former seem to be a subset of the directories in `Payload/<app_name>.app/Frameworks` in the IPA.
            * Results (for old dataset from proj-ios): `with iabtcf: 0, with any cerifified CMP: 28, total: 1001`
* Consequences for analysis


TODO:

* Explain OpenRTB?
* DPA decision
* Introduce taxonomy
    * dialog
    * notice
    * link
-->
