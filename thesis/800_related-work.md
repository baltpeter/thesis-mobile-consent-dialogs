# Related Work

TODO: Probably move this to the end, we need to talk about many concepts that are only later introduced in the thesis.

## Analysis of Consent Dialogs and Privacy Policies

Prior research into consent dialogs in the wild has so far been almost exclusively limited to the web. 

* Dark Patterns after the GDPR: Scraping Consent Pop-ups and Demonstrating their Influence (2020) [@nouwensDarkPatternsGDPR2020]
    * Scraped 680 from top 10k UK sites for CD design based on top 5 CMPs
    * found common dark patterns
* We Value Your Privacy ... Now Take Some Cookies: Measuring the GDPR's Impact on Web Privacy (2019) [@degelingWeValueYour2019]
    * monitored changes in website privacy practices between December 2017 and October 2018
    * found 72.6 % updating PP and up to 15.7 % adding new ones
* (Un)informed Consent: Studying GDPR Consent Notices in the Field (2019): [@utzInformedConsentStudying2019a]
    * manually looked at screenshots of 1000 CD and identified 8 variables based on [@degelingWeValueYour2019]: size, position, blocking, choices (implicit, binary, categories, vendors), text, neduging, formatting, PP link
* Cookie dialogs and their compliance (2021) [@aertsCookieDialogsTheir2021]
    * detected CD on EU websites based on filter list and TCF
    * compared cookies with Cookiepedia
    * detected accept buttons highlighted compared to reject button
* Do Cookie Banners Respect my Choice?: Measuring Legal Compliance of Banners from IAB Europe’s Transparency and Consent Framework (2020) [@matteCookieBannersRespect2020]
    * analyzed CDs using TCF
    * detected violations: consent registered without user interaction, preselected options, consent registered even after opt-out
* A Cross-Platform Evaluation of Privacy Notices and Tracking Practices [@mehrnezhadCrossPlatformEvaluationPrivacy2020]
    * manually analysed CDs in 116 websites and their corresponding apps
    * founds CDs in 91% of websites and 35% of apps
* The Impact of User Location on Cookie Notices (Inside and Outside of the European Union) [@eijkImpactUserLocation2019a]
    * detect CDs based on adblocker list
    * find 40% of sites having any dialog or notice
    * differences in CD prevalences between countries, mostly based on the site, not user country
* Purposes in IAB Europe’s TCF: which legal basis and how are they used by advertisers? [@mattePurposesIABEurope2020a]
    * study purposes in IAB TCF and their usage by advertisers, finding many advertisers lacking a valid legal basis under the GDPR
* noyb aims to end “cookie banner terror” and issues more than 500 GDPR complaints
* In May 2021, consumer protection organisation noyb analysed popular websites using the OneTrust CMP and found violations in more than 500 sites, with the most common ones being sites making it harder to refuse and withdraw consent than giving it and highlighting the "accept" over the "reject" button [@noyb.euNoybAimsEnd2021].

* Harkous et al. [@harkousPolisisAutomatedAnalysis2018] and Hossein et al. [@hosseiniUnifyingPrivacyPolicy2021] propose machine-learning approaches for analysing privacy policies.
* Zimmeck et al. specifically analysed the privacy policies of Android apps and compared them against the apps' permissions, API usage, and library inclusion [@zimmeckMAPSScalingPrivacy2019].

## ~~Experiments on~~ Consent Dialog Design and Dark Patterns

Consent fatigue and effect of nudging on consent rates well established. Users will often use the easiest choice to dismiss a consent dialog as quickly as possible, without thinking about what it entails. Companies commonly exploit this by highlighting the most privacy-invasive choice and making it harder to choose anything else.

* Trained to Accept? A Field Experiment on Consent Dialogs (2010) 
    * Found that users are trained to accept EULAs and tend to blindly accept anything that resembles them.
    * Further found that button text had the largest effect on consent rates, with button labels indicating an actual choice resulting in much fewer opt-ins.
* A comparison of users' perceptions of and willingness to use Google, Facebook, and Google+ single-sign-on functionality [@bauerComparisonUsersPerceptions2013]
    * 2013
    * Experiment that investigated users' perception of and willingness to use "log in with <social network>" functionality, also looking at the dialogs that prompt for consent to forward the user's information to third-party provider.
    * Already found that consent dialogs don't work as a medium for conveying privacy-critical information to users, even when those users are concerned about their privacy
* Tales from the Dark Side: Privacy Dark Strategies and Privacy Dark Patterns [@boschTalesDarkSide2016]
    * introduce a series of dark patterns common in websites and apps to deceive users into agreeing to more privacy-invasive practices than they actually want

Already some research on human aspects of CDs specifically under the GDPR:

* again: [@nouwensDarkPatternsGDPR2020]
    * also experiment investigating how designs affect user choices finding that dark patterns increase consent rates
* again: [@utzInformedConsentStudying2019a]
    * experiments that investigated effect of the variables on interaction and whether consent was given
    * found that nudging, even small design details, can heavily influence consent rates
* Dark and Bright Patterns in Cookie Consent Requests [@grasslDarkBrightPatterns2021]
    * found most participants agreeing to all consent requests regardless of dark patterns
    * hypothesise that nudging in consent dialogs has been so common for a long time that people become conditioned to them and their behaviour is influenced even in the absence of nudges
    * conversely, found that "bright patterns", i.e. nudging towards the privacy-friendly option, was effective in making people choose that
* Multiple Purposes, Multiple Problems: A User Study of Consent Dialogs after GDPR (2020) [@machuletzMultiplePurposesMultiple2020a]
    * experiment that explores users' interactions with CDs
    * found that a highlighted "accept all" button results in significantly higher consent rates but at the same time users are not aware of its effect and regret their choice after being informed of the effect that accepting had
    * based on that, they call the morality and legitimacy of "accept all" buttons into question
* Fassl et al. present a literature review, also looking at potential solutions to the discovered problems [@fasslStopConsentTheater2021].
* Gray et al. [@grayDarkPatternsLegal2021] present a transdisciplinary *interaction criticism* of dark patterns in consent dialogs, providing arguments for further policy refinement and advancement.

## Traffic Analysis of Websites and Apps

> More generally, for privacy violations on Android, two 2019 studies by Liu et al. (https://ieeexplore.ieee.org/abstract/document/8660581) and He et al. (https://www.sciencedirect.com/science/article/abs/pii/S2214212618304356) detected privacy leaks from third-party libraries based on static and dynamic analysis. Two 2016 studies by Slavin et al. (https://dl.acm.org/doi/abs/10.1145/2884781.2884855) and Yu et al. (https://ieeexplore.ieee.org/abstract/document/7579770) compared apps' privacy policies with the tracking code used in them based on text analysis.  
> On iOS, research into privacy violations by apps, is scarce and outdated. A 2011 paper by Egele et al. explored using static analysis on app binaries to detect privacy leaks (http://www.syssec-project.eu/m/page-media/3/egele-ndss11.pdf) and a 2015 paper by Dehling et al. crawled app store pages of health apps (https://mhealth.jmir.org/2015/1/e8/PDF).

* 4 Years of EU Cookie Law: Results and Lessons Learned (2019) [@trevisanYearsEUCookie2019a]
    * CookieCheck tool that visits websites, doesn't provide consent, and checks whether tracking cookies (as classified by Ghostery and Disconnect) have been set
    * found that 74% of websites use third-party cookies
* Share First, Ask Later (or Never?) - Studying Violations of GDPR's Explicit Consent in Android Apps [@nguyenShareFirstAsk2021]
    * analysis of network traffic of 86k Android apps with no interaction
    * classified contacted domains by whether they are third-party trackers
    * found that 25k apps contacted trackers without consent
    * survey to find out controller's awareness of GDPR requirements
* User Tracking in the Post-cookie Era: How Websites Bypass GDPR Consent to Track Users (2021) [@papadogiannakisUserTrackingPostcookie2021b]
    * consider "post-cookie" tracking techniques like fingerprinting and tracking ID synchronisation
    * found that user choice in dialogs matters little with 75% of the detected tracking happening before the user interacted with a consent prompt or after even explicitly rejecting it
* Decrease in cookie and third-party tracking use since the GDPR, to a certain degree also profiting people in non-EU countries [@huCharacterisingThirdParty2019a; @dabrowskiMeasuringCookiesWeb2019]
* MadDroid: Characterizing and Detecting Devious Ad Contents for Android Apps [@liuMadDroidCharacterizingDetecting2020]
    * MadDroid, framework for automatically detecting malicious ad content in Android apps
    * found 6% of apps having malicious ads
* Bug Fixes, Improvements, ... and Privacy Leaks - A Longitudinal Study of PII Leaks Across Android App Versions [@renBugFixesImprovements2018]
    * compared various versions of 512 Android apps across 8 years, finding increased collection of personal data over time

* The AppChk Crowd-Sourcing Platform: Which Third Parties are iOS Apps Talking To? [@geierAppChkCrowdSourcingPlatform2021]
    * app that creates local VPN, allowing them to collect the contacted domains
    * the *App Privacy Report*, a similar feature, has since been integrated iOS itself (starting with iOS 15.2) [@appleinc.AppPrivacyReport2021]
* Are iPhones Really Better for Privacy? A Comparative Study of iOS and Android Apps: [@kollnigAreIPhonesReally2022]
    * compared privacy practices of 12k apps each on Android and iOS
    * found widespread violations against applicable privacy regulation and little difference between the platforms

* Exodus, tracking adblock lists
* https://trackercontrol.org
