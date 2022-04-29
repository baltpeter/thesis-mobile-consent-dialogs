# Discussion

## Comparison with Results for the Web

Here, we compare our results with the findings from previous research for the web to gauge the differences between the two platforms.

Prevalence of consent elements
:   Eijk et al. found 40.2% of 1500 from the top 100 websites across multiple countries having any consent dialog or notice in 2019 [@eijkImpactUserLocation2019a], and Sanchez-Rola et al. report around 50% in 2000 websites the same year [@sanchez-rolaCanOptOut2019], while Mehrnezhad reports 91% in the top 116 EU websites in 2020 [@mehrnezhadCrossPlatformEvaluationPrivacy2020].  
    Meanwhile, we found 17.89% of all apps having a dialog, notice, or link. Even taking into account our observed false negatives and disregarding the result by Mehrnezhad as an outlier likely influenced by the significantly smaller sample size, these numbers are noticably higher than our results, suggesting that consent elements are less common on mobile than on the web.

    Some research also looked at CMP providers according to IAB TCF data. Matte et al. found Quantcast, OneTrust, Didomi, and Sourcepoint being the most common CMPs in 2020 [@matteCookieBannersRespect2020], while Aerts encountered Didomi, Sourcepoint, LiveRamp, and OneTrust most frequently in Belgian, Dutch, and French sites in 2021 [@aertsCookieDialogsTheir2021].  
    These results are similar to our findings. We also encountered all of these CMPs on mobile, though with different distributions. Notably, our second most common CMP was Google which Matte et al. did not encounter at all and Aerts encountered less frequently. This can be explained by the fact the Google first adopted the TCF in July 2020 [@carteeGoogleAddedIAB2020].

Dark patterns in consent dialogs
:   Nouwens et al. found only 12.6% of consent dialogs having a "reject all" button on the first layer in 2020 [@nouwensDarkPatternsGDPR2020], while Mehrnezhad found 35.4% of websites only having an "accept" and no "reject" button the same year [@mehrnezhadCrossPlatformEvaluationPrivacy2020]. Similarly, Aerts found significantly more first-layer "accept" than "reject" button and they also found the "accept" button commonly having a different colour than the "reject" button in 2021 [@aertsCookieDialogsTheir2021]. Of the violations that noyb sent complaints about in 2021, 81% were about dialogs on websites with no "reject" button on the first layer and 73% were about "accept" buttons that were highlighted by colour compared to the "reject" button [@noyb.euNoybAimsEnd2021].  
    In comparison, we found 43.2% of dialogs on mobile having an "accept" but no "reject" button on the first layer and 31.2% of dialogs highlighting the "accept" button by colour.

## Limitations {#sec:discussion-limitations}

There are some limitations in our approach that need to be considered when looking at the results.

Detection of consent dialogs and dark patterns
:   As explained, our analysis can only provide a lower bound on the prevalence of consent elements in apps and of dark patterns in consent dialogs. This is in part due to the limited tooling for dynamically analysing apps on mobile devices. For one, Appium can only detect text that the apps expose in a machine-readable way, which is not always the case. We especially saw games rendering text as bitmaps that are opaque to Appium and thus missed by us. Also, Appium can only access a limited amount of element attributes. For example, it cannot extract a extract a link's target URL or even reliably classify an element as a link. This especially impacts our ability to detect privacy policy links, meaning that we have to rely on the link text alone.

    Additionally, we are limited by our very general approach of detecting arbitrary consent elements based on string matching, which greatly limits the details we can extract from apps and forces us to err on the side of caution at the cost of missing consent elements that our strict regexes do not catch (cf. [@sec:cd-situation-consequences]). We also only match strings in English or German, though the impact of that is likely within reason as we only downloaded apps from the top charts for Germany anyway.

    Finally, we do not interact with apps beyond their consent dialogs. This means that we can only find consent elements that are displayed on the initial screen after launching the apps and will miss those that are only displayed later in the user flow, e.g. after a first-run wizard.

Possible differences in consent dialog behaviour due to analysis environment
:   Even though we clear all app data between runs, it is possible that apps try to re-identify the device for example using our IP address or through fingerprinting, which could impact our results on changes between the user accepting and rejecting the dialog. New techniques continue outsmarting fingerprinting protections in browsers time and time again [@acarWebNeverForgets2014; @rAreYouAnonymous2021; @solomosTalesFaviconsCaches2021] and mobile devices are no strangers to fingerprinting, either [@zhangSensorIDSensorCalibration2019; @coplandDeviceFingerprintingAndroid2020]. Given the vast array of vectors for fingerprinting and the fact that there likely even exist many that are not publicly known, we cannot possibly control all of them and thus have to assume that apps are able to track us even across resets.

    In addition, we deny the permission for tracking across other companies' apps and websites as apps might otherwise construe that as consent (regardless of whether it would be legally speaking). Conversely, it is however possible that apps interpret us denying this permission as a refusal of consent and thus don't display a consent dialog. While this would actually in the users' interest, it would skew our results on the prevalence of consent dialogs.

App instrumentation framework
:   We were not able to launch a significant number of apps on Android: 31.66% of the apps quit immediately or shortly after being started. Manual investigation of a random sample of those revealed that this was caused by objection's certificate pinning bypass. Instead starting the app without the bypass worked fine. Other Frida scripts for bypassing certificate pinning^[For example these: <https://github.com/httptoolkit/frida-android-unpinning> and <https://codeshare.frida.re/@pcipolloni/universal-android-ssl-pinning-bypass-with-frida/>] had the same problem. We suspect that this is due to some sort of anti-tamper protection built into the apps, perhaps even one built into a common network library and thus automatically included in this many apps. Ultimately, we decided to exclude the affected apps from our analysis rather than running them without a certificate pinning bypass as we feared they would otherwise skew our results with regards to the network traffic and tracking analysis.

    It is also possible that the way we run the apps affects their behaviour. Apps can trivially detect that they are running on a rooted/jailbroken device and in an emulator on Android, as well as the fact that we are injecting Frida scripts into them[^fridaantiroot]. For example, we saw apps that displayed a screen informing us that we are using a rooted device and refused to function as a result. This was especially common with banking apps.

    Similarly, our HTTPS proxy could also alter some apps' behaviour. If an app employs certificate pinning in a way that is not bypassed by objection or SSL Kill Switch 2, the corresponding requests will fail, which may have an effect on the app behaviour.


[^fridaantiroot]: There are Frida scripts to bypass these checks as well, e.g.: <https://codeshare.frida.re/@dzonerzy/fridantiroot/> and <https://codeshare.frida.re/@enovella/anti-frida-bypass/>

    However, we tried to keep the amount of Frida scripts we inject to a minimum because they can in fact break apps as we saw. The only script that we inject into the apps during the actual runs is the certificate pinning bypass on Android. All other scripts are either injected into system processes (clipboard seeding and granting location permission on iOS), where we have confirmed that they don't cause problems, or are only injected into the app after the rest of analysis is done (reading the preferences).
