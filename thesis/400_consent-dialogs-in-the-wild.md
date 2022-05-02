# Consent Dialogs in the Wild

In this chapter, we explore how consent dialogs are actually implemented in the wild, both on the web and on mobile, to gain insights on which approach to use for the analysis in [@Sec:analysis-method].

## Situation on the Web

It makes sense to first take a look at consent dialogs on the web because most prior research [@utzInformedConsentStudying2019a; @eijkImpactUserLocation2019a; @matteCookieBannersRespect2020; @nouwensDarkPatternsGDPR2020] on the topic focusses exclusively on the web.

### Consent Management Platforms

Various companies offer *consent management platforms* (CMPs), off-the-shelf solutions that website operators can embed into their site under the promise that they will ensure legal compliance for tracking and similar processing [@onetrustllc.OneTrustConsentManagement; @usercentricsgmbhWebsiteConsentManagement2022; @cookiebotCookiebotConsentManagement2020; @piwikprosaPiwikPROConsent2022]. Using a CMP means that individual websites don't have to implement consent dialogs themselves anymore. As such, CMPs are also conducive to research as one now only needs to handle a handful of CMPs instead of custom implementations on every website.

Theoretically, CMPs should also make it easier for websites to follow the law as the CMP is responsible for ensuring that processing that requires consent (like tracking or setting corresponding cookies) only happens after consent has been given by the user. However, most CMPs are highly configurable and allow the website operators to enable behaviour that violates the law; sometimes such settings are even the default [@noyb.euWeComplyGuideOneTrust2021].

On the web, usage of CMPs is common. Recent research detected the use of CMPs on between 6&nbsp;% and 13&nbsp;% of European websites, depending on their Tranco rank [@hilsPrivacyPreferenceSignals2021; @matteCookieBannersRespect2020]. Ad tech company Kevel reports the presence of a CMP on 44&nbsp;% of the top 10k US sites for Q1 2022 [@kevelConsentManagementPlatform2022].

### IAB Transparency & Consent Framework {#sec:cd-tcf-web}

Websites often use third-party scripts from many different vendors for all kinds of purposes, including advertising and tracking. Many of these require consent (see [@Sec:legal-background]). How do websites make sure that the scripts only start processing after the required consent has been given? Without a common framework, either each CMP would have to implement custom handlers for each possible third-party script or each third-party script would need to know how to communicate with all possible CMPs.

IAB Europe, an association that represents the interests of the digital advertising and marketing industry in Europe [@iabeuropeUs2021], maintains the Transparency & Consent Framework (TCF), a standard that defines a common interface for CMPs and third-party scripts to communicate. It defines how websites should store consent and legitimate interest records, as well as conditions on how to prompt the user for consent and inform them through consent dialogs. For that, IAB Europe maintains a list of purposes and vendors the website can ask users to consent to. The first version, v1.1^[Version 1.0 was never published.], was launched in April 2018, shortly before the GDPR went into force, and in August 2019, a revised v2.0 was published, with v1.1 now being deprecated [@iabeuropeTCFTransparencyConsent2021].  
Most CMPs implement the TCF [@onetrustllc.OneTrustPreferenceChoiceCMP2022; @usercentricsgmbhTCFExplainedMost2020; @iubendas.r.lCompleteGuideIubenda2020; @cookiebotIABTransparencyConsent2022]. Note that in February 2022, the Belgian Gegevensbeschermingsautoriteit found the TCF to violate the GDPR in a joint decision with other DPAs but gave the IAB a grace period of six months to implement the necessary changes [@gegevensbeschermingsautoriteitlitigationchamberDecision2120222022].

The TCF distinguishes between the publisher (the entity running the website), the CMP (the entity providing the CMP—this can also be a publisher's in-house CMP if it is registered with IAB Europe), and vendors (the third-parties embedded in the publisher's website, e.g. ad or tracking providers). Both CMPs and vendors need to register with IAB Europe, for which there is an annual fee of 1,500 € [@iabeuropeJoinTCF2021].

On a technical level, the TCF mainly regulates two aspects. For one, it mandates that CMPs store consent records in the so-called TC string, which encodes^[IAB Europe offers a JavaScript library (<https://github.com/InteractiveAdvertisingBureau/iabtcf-es>) and an online tool (<https://iabtcf.com>) to decode and encode TC strings.] the following information [@iabtechlabTransparencyConsentString2022]:

* Metadata: TCF version the TC string is based on, last update time
* Consent records: per purpose and per vendor
* Legitimate interest records: objections to them by the user^[The fact that the TCF allows a publisher to use a legitimate interest for a certain processing does not necessarily mean that this is legal [@mattePurposesIABEurope2020].]
* Publisher restrictions: allow the publisher to specify custom requirements to restrict how vendors may process personal data
* Publisher transparency and consent data: allows the publisher to store consent and legitimate interest data for their own purposes
* Jurisdiction data: country publisher is based in

TC strings may only be created or changed by the CMP [@iabtechlabTransparencyConsentString2022], and the CMP is free to choose where and how to store the TC string [@iabtechlabIABEuropeTransparency2021].

Secondly, it defines mechanisms for the different parties to communicate. For that, the CMP must expose API commands through the `__tcfapi(command, version, callback, parameter)`{.js} function on the global `window`{.js} object [@iabtechlabConsentManagementPlatform2021], most notably a command to receive an object representing the parsed TC string, one to check whether the CMP has finished loading and whether it believes the GDPR applies in the context of this visit^[The TCF does not mandate how the CMP is supposed to determine whether the GDPR applies, it only mentions using the user's geolocation as one option. Vendors are required to adhere to the CMP's determination. [@iabtechlabConsentManagementPlatform2021] However, as explained in [@sec:bg-gdpr], the user's location alone is not necessarily sufficient for determining whether the GDPR applies.], and another one to register an event listener for changes to the TC string.

If script then wants to start processing, it has to [@iabtechlabConsentManagementPlatform2021]:

1. Determine whether a CMP is loaded on the page by checking for the presence of the `__tcfapi()`{.js} function. If no CMP is loaded, it has to assume that there is no consent or legitimate interest.

   If the script is loaded in an iframe instead of directly on the page (common for ads), it can use a `postMessage()` API for the same purpose.
2. Request the TC data, and check whether a legal basis for the desired processing is available. Only if that's the case may it start processing.
3. Subscribe to change events to notice if the user withdrew their consent for example and then stop processing accordingly.

While not the TCF's intended purpose, the fact that the CMP data can be easily read programmatically through the API that has to be provided has also enabled research on consent dialogs on the web [@hilsPrivacyPreferenceSignals2021; @matteCookieBannersRespect2020; @aertsCookieDialogsTheir2021], and is even used by consumer protection organizations to automatically find violations in popular websites to pursue legal action against [@noyb.euNoybAimsEnd2021].

## Situation on Mobile {#sec:cd-situation-mobile}

In this section, we look at whether mobile apps also commonly implement the TCF or at least use a limited number of CMPs, which would make the desired analysis easy.

### Use of IAB TCF {#sec:cd-situation-mobile-tcf}

Version 2.0 of the IAB TCF also supports CMPs in mobile apps on Android and iOS [@iabtechlabConsentManagementPlatform2021]. As native apps do not support running JavaScript code, a different API mechanism is used here. CMPs must instead store consent details (including the TC string) via the platform-specific per-app storage interfaces, namely `SharedPreferences` on Android and `NSUserDefaults` on iOS. Vendor SDKs can also access these stores to read the TCF data and set listeners to be informed of updates, thus the same steps as on the web can be used to determine whether an SDK can process the user's data on mobile, just with a slightly different implementation.

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

In both cases, for automated analysis, the objects would still need to be converted from their respective platform-native representation to a common format but that step is omitted here for brevity.

Unlike on the web, no prior research on how common TCF usage is on mobile exists as far as we are aware. To gauge whether reading the TCF preferences is a viable approach for this thesis, we performed a simple analysis on 823 apps from a dataset of popular Android apps from November 2021: The apps were run in the Android emulator and left running for five seconds. Afterwards, a screenshot was taken and the `SharedPreferences` of the respective app were saved. Then, we manually looked at the screenshots to determine whether the app showed any reference to data protection (like a consent dialog, a privacy notice, or even just a link to a privacy policy).

181 of the 823 (21.99&nbsp;%) apps displayed such a reference to data protection on screen after five seconds. However, only 21 of the 823 apps (2.55&nbsp;%) had set a corresponding privacy-related preference (i.e. one with a key that includes `IABTCF` or `GDPR`). This suggests that the IAB TCF is not commonly implemented on mobile.

### Use of CMPs

Even though it seems like mobile apps do not tend to make use of the TCF, it would still be possible that they use off-the-shelf CMPs that just don't implement the TCF. To find out whether that is actually the case, we ran a simple static analysis to detect the presence of common CMP libraries in Android and iOS apps.

On Android, we use the same approach that the Exodus privacy project uses for checking for the presence of tracking libraries [@exoduscontributorsExodusStaticAnalysis2018]. We run the `dexdump` tool on the APK file, which is the Android counterpart to the Linux `objdump` tool and can statically extract class and method names from an APK, among other things. Then we compare the namespaces of the listed classes to a list of CMP libraries. For example, the classes of the Didomi CMP library are in the `io/didomi` namespace. If we detect classes with this namespace in an app, we can assume that it uses the CMP^[Of course, this approach is very fuzzy. Even if an app includes a CMP library, that does not mean it actually uses it. In addition, it is possible that the list of namespaces we use is not strict enough and matches other non-CMP libraries. None of that is a problem for the purposes of this analysis, though. Its goal is only to provide an upper bound on the CMP usage in mobile apps and to evaluate whether it is viable at all to rely on CMP-specific code for this thesis.].

On iOS, we are not aware of any similar work. It is however possible to list the shared libraries in an IPA file using the `otool` command [@benaneeshAnswerHowSearch2016], where the lines starting with `@rpath` are the libraries included in the IPA (lines without this prefix are system libraries). The symbol table can be listed using the `nm` and `symbols` commands [@columboAnswerFindSize2015]. All of these tools only run on macOS.  
Nonetheless the required functionality can be replicated on any operating system: An IPA file is just a ZIP archive. All libraries included in an IPA are in subdirectories of `/Payload/<app name>.app/Frameworks`{.placeholders}. We simply list those directories and compare them against a list of CMP libraries.

For this analysis, we compiled a list of identifiers for the names of 18 CMPs (based on [@iabeuropeCMPList2021; @udonisTop14Consent2022; @instabugTopMobileApp2021]). For Android, we used the same dataset as in [@sec:cd-situation-mobile-tcf] but ran the analysis on all 3,271 apps. For iOS, we used a dataset of 1,001 apps from the App Store top charts from May 2021.

We detected a potential CMP use in 234 of the 3,271 Android apps (7.15&nbsp;%) and 28 of the 1,001 iOS apps (2.8&nbsp;%). We also checked for the presence of IAB's TC string library (`com/iabtcf`), which is only available for Android. We detected that in 38 of the 3,271 apps (1.16&nbsp;%). This suggests that mobile apps don't commonly use off-the-shelf CMPs either, especially given that the simple analysis we performed is even an overapproximation.

### Consequences for Analysis {#sec:cd-situation-consequences}

As established in this section, we can neither rely on the TCF, which would have provided a standardized and machine-readable way to detect the presence of a CMP in an app, read the settings of CMPs, and even interact with them, nor on custom adapters for the internal implementions and dialog design characteristics of a limited number of off-the-shelf CMP solutions. As such, we need to use a much more general approach that detects and works with any kind of CMP, regardless of implementation details. This in turn necessarily means a loss in the amount of details we can extract from CMPs, as we have to expect a large amount of completely different implementations. It also means that we will likely miss some consent dialogs.  
The details of the method we use for the analysis are described in [@Sec:analysis-method].

For the few consent dialogs that _do_ implement the TCF, we still extract the data from `NSUserDefaults` or `SharedPreferences` and perform an analysis on that.
