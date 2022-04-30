# Conclusion

In this thesis, we explored the implementation consent dialogs in mobile apps. We looked at the legal framework that regulates data protection in mobile apps, identifying the GDPR and ePD as the primary laws which limit the processing that apps can perform and which mandate that apps need the user's informed consent in order to legally perform tracking.

We then established the strict criteria for a legally compliant consent dialog stemming from the GDPR, which prohibit dark patterns and nudging, e.g. prioritising the "accept" button, using vague purpose descriptions like "to improve user experience", making it harder to refuse consent than accept it, and preselecting puposes. Any consent dialog that violates even just one of these criteria cannot capture valid consent, leaving the app without a legal basis for the data processing.

Looking at consent dialogs in the wild, we found that while websites commonly make use of the IAB TCF standard to implement consent dialogs, this is not the case on mobile, with only around 3&nbsp;% of apps adhering to the TCF. Similarly, apps less frequently use off-the-shelf CMP solutions compared to the web.

To perform a large-scale analysis of apps on Android and iOS, we developed a device instrumentation framework that can manage apps, set app permissions and extract app preferences using Frida, collect the device network traffic through mitmproxy (including HTTPS and certificate-pinned traffic thanks to objection and SSL Kill Switch 2) while an app is running, as well as analyse and interact with elements displayed on screen by leveraging Appium. We also showed how to collect top chart data for the Google Play Store and the Apple App Store. To actually download the apps, we used PlaystoreDownloader for Android and extended IPATool with support for "buying" apps for iOS.

For the actual detection of references to data protection in the apps, we employed a list of regexes to find the relevant elements and distinguished the discovered references between dialogs, notices, and links. In the detected dialogs, we checked for ambiguous button labels, missing "reject" buttons, "accept" buttons highlighted by colour or size, and apps that quit after refusing consent. While running the apps, we recorded their network traffic and extracted the transmitted data using endpoint-specific tracking requests adapters and indicator matching.

Finally, we evaluated the collected data and found that more than 30&nbsp;% of the total network traffic was tracking, with Google and Facebook being the most prevalent tracking companies by far. Almost 73&nbsp;% of apps sent requests containing pseudonymous data even before any user interaction.  
We further found that around 18&nbsp;% of apps displayed any consent element on screen in the first run, with 8.75&nbsp;% showing a consent dialog, 4.44&nbsp;% showing a notice, and 4.69&nbsp;% showing a link to a privacy policy. Of those dialogs, more than 90&nbsp;% exhibited at least one of the dark patterns we detect, missing "reject" buttons being the most common, followed by ambiguous button labels and "accept" buttons that were highlighed by colour. We did however not observe all of the apps with a dialog transmitting pseudonymous data. In total, we found 77.34&nbsp;% of the apps with a dialog employing dark patterns _and_ transmitting pseudonymous data, thus violating the GDPR. Given the nature of our approach, these numbers are only a lower bound and there are likely even more violations.

Given that the vast majority of consent dialogs are in direct violation of the GDPR, it seems fair to conclude that the GDPR is not at fault for the flood of annoying consent dialogs and that it is in fact the lack of enforcement of the GDPR that allows these user-hostile practices to continue.

## Future Work

The analysis presented in this thesis gave a first snapshot into consent dialogs in mobile apps as of early 2022. Future research could monitor changes over time as has already been done for the web. It could be especially interesting to monitor how Google following Apple's footsteps with the potential to opt-out of the advertising ID and the introduction of a privacy label counterpart influences the situation on Android. We hope that we can contribute to that by releasing our source code.

Of course, subsequent work should also try to solve the limitations discussed in the previous chapter. The certificate pinning bypass problems on Android are especially unfortunate and force us to exclude a significant amount of apps from analysis. Improving certificate pinning bypasses could also benefit research into other subjects on mobile. In addition, there are hopefully more reliable ways to inspect app elements and extract more details about consent dialogs.

Going further, we only interacted with the consent dialogs, which means that the vast majority of app functionality is left untouched by us. App interaction beyond consent dialogs for data protection research could not rely on naive monkey testing but would need to be context-aware to avoid acidentally granting unwanted consent.

Finally and orthogonally to our research, until enforcement catches up with the law and progress in tracking technology, defenses against tracking in general and metadata extraction in particular are needed to preserve users' privacy.

\renewcommand{\href}[2]{\originalHref{#1}{#2}}

<!-- Force references to be displayed here, see: https://stackoverflow.com/a/44294306 -->
# Bibliography

\markright{{\thechapter}. Bibliography}

\begingroup

\sloppy

<div id="refs"></div>

\endgroup
