# Discussion

## Comparison with Results for the Web

* Dark Patterns after the GDPR: Scraping Consent Pop-ups and Demonstrating their Influence [@nouwensDarkPatternsGDPR2020]
    * assuming consent without user action: 32.5 % of sites with CMP
    * 50.3%/49.7% barrier vs. banner
    * 50.1% of CMPs no 'reject all'
    * 12.6% of CMPs 'reject all' on first page
* 4 Years of EU Cookie Law: Results and Lessons Learned (2019) [@trevisanYearsEUCookie2019a]
    * "67 out of 241 websites do not provide a Cookie Bar to let users provide consent, but install some profiling cookies anyway. Among the remaining ones, only 7% wait for user’s consent before installing profiling cookies."
* Cookie dialogs and their compliance (2021) [@aertsCookieDialogsTheir2021]
    * TCF data analysis: p. 36 et seq.
    * cookie data: p. 43 et seq.
    * accept highlighted: p. 56 et seq.
* Do Cookie Banners Respect my Choice?: Measuring Legal Compliance of Banners from IAB Europe’s Transparency and Consent Framework (2020) [@matteCookieBannersRespect2020]
    * TODO
* A Cross-Platform Evaluation of Privacy Notices and Tracking Practices [@mehrnezhadCrossPlatformEvaluationPrivacy2020]
    * Privacy notice in 32% of apps, but not just the very first page: also manually dismissed alerts and skipped first run wizards
    * Only 2% (of all apps) with link only. (TODO: We probably match too many links but not that extreme). Might be due to only analysing 101 apps based on Alexa top 150 websites. Their reporting of 91% CDs on websites is also a lot higher than other literature. (TODO: analyse verdict vs. position)
    * TODO: accept highlight, no accept
* Can I Opt Out Yet?: GDPR and the Global Illusion of Cookie Control [@sanchez-rolaCanOptOut2019]
    * ~50% with any dialog or notice
    * ~30% notices
* The Impact of User Location on Cookie Notices (Inside and Outside of the European Union) [@eijkImpactUserLocation2019a]
    * 40.2% with any dialog or notice
* noyb aims to end “cookie banner terror” and issues more than 500 GDPR complaints [@noyb.euNoybAimsEnd2021]
    * violations graph (note: percentage of complaints, not all sites!)

## Limitations {#sec:discussion-limitations}

* No interaction with apps beyond consent dialog (e.g. first-run wizards not considered)
* Only considers text that is machine-readable and available to Appium (e.g. games are often essentially images that Appium can't "read")
* Only DE and EN supported
    * only DE app stores anyway
* Appium can only access a very limited amount of element attributes
* Analysis provides lower bound
* Launching TODO % of Android apps failed due to certificate pinning bypass
* Apps can trivally detect emulator/root/jailbreak, some change their behaviour based on that (e.g. make it impossible to use app)
* HTTPS proxy can alter behaviour of apps. If app uses cert pinning and we don't manage to bypass that, the corresponding requests will fail, which may have an effect on the app behaviour.
