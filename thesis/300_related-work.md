# Related Work

TODO: Probably move this to the end, we need to talk about many concepts that are only later introduced in the thesis.

## Traffic analysis of websites and apps

* Share First, Ask Later (or Never?) - Studying Violations of GDPR's Explicit Consent in Android Apps [@nguyenShareFirstAsk2021]
    * analysis of network traffic of 86k Android apps with no interaction
    * classified contacted domains by whether they are third-party trackers
    * found that 25k apps contacted trackers without consent
    * survey to find out controller's awareness of GDPR requirements
* 4 Years of EU Cookie Law: Results and Lessons Learned (2019) [@trevisanYearsEUCookie2019a]
    * CookieCheck tool that visits websites, doesn't provide consent, and checks whether tracking cookies (as classified by Ghostery and Disconnect) have been set
    * found that 74% of websites use third-party cookies

## Analysis of CDs on the web

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

## Experiments on CD design and dark patterns

* again: [@nouwensDarkPatternsGDPR2020]
    * also experiment investigating how designs affect user choices finding that dark patterns increase consent rates
* again: [@utzInformedConsentStudying2019a]
    * experiments that investigated effect of the variables on interaction and whether consent was given
    * found that nudging, even small design details, can heavily influence consent rates

---

* A Comparison of Users’ Perceptions of and Willingness to Use Google, Facebook, and Google+ Single-Sign-On Functionality (2013): https://dl.acm.org/doi/pdf/10.1145/2517881.2517886
* Stop the Consent Theater (2021): https://sci-hub.se/https://dl.acm.org/doi/abs/10.1145/3411763.3451230
    * literature review
* Multiple Purposes, Multiple Problems: A User Study of Consent Dialogs after GDPR (2020): https://sciendo.com/article/10.2478/popets-2020-0037
    * experiment that explores users' interactions with CDs
* Trained to Accept? A Field Experiment on Consent Dialogs (2010): https://sci-hub.se/https://dl.acm.org/doi/abs/10.1145/1753326.1753689
* I consent: An analysis of the Cookie Directive and its implications for UK behavioral advertising (2012): https://journals.sagepub.com/doi/abs/10.1177/1461444812458434
* User Tracking in the Post-cookie Era: How Websites Bypass GDPR Consent to Track Users (2021): https://sci-hub.se/https://dl.acm.org/doi/abs/10.1145/3442381.3450056
* Characterising Third Party Cookie Usage in the EU after GDPR (2019): https://sci-hub.se/https://dl.acm.org/doi/abs/10.1145/3292522.3326039
* The Impact of User Location on Cookie Notices (Inside and Outside of the European Union) (2019): https://pure.tudelft.nl/ws/files/57080768/vaneijk_conpro19.pdf
* MadDroid: Characterizing and Detecting Devious Ad Contents for Android Apps: https://arxiv.org/pdf/2002.01656.pdf
* Polisis: Automated Analysis and Presentation of Privacy Policies Using Deep Learning: https://pribot.org/files/Polisis_USENIX_Security_Paper.pdf
* Are iPhones Really Better for Privacy? A Comparative Study of iOS and Android Apps: https://sciendo.com/article/10.2478/popets-2022-0033
* Dark Patterns and the Legal Requirements of Consent Banners: An Interaction Criticism Perspective: https://hal.inria.fr/hal-03117307/document
* Dark and Bright Patterns in Cookie Consent Requests: https://jdsr.se/ojs/index.php/jdsr/article/view/54
* Purposes in IAB Europe’s TCF: which legal basis and how are they used by advertisers? [@mattePurposesIABEurope2020a]
* Unifying Privacy Policy Detection: https://www.sciendo.com/article/10.2478/popets-2021-0081

* TODO: noyb
