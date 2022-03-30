# Analysis Method {#sec:analysis-method}

## Consent Dialog Detection

### Existing Research for the Web

* Many purely manual approaches (https://www.researchgate.net/publication/332888923_4_Years_of_EU_Cookie_Law_Results_and_Lessons_Learned, https://sci-hub.se/https://dl.acm.org/doi/abs/10.1145/3321705.3329806, https://www.researchgate.net/profile/Martin-Degeling/publication/334965379_Uninformed_Consent_Studying_GDPR_Consent_Notices_in_the_Field/links/5d638e6c458515d610253bb1/Uninformed-Consent-Studying-GDPR-Consent-Notices-in-the-Field.pdf)
* Some with CMP-specific adapters: https://sci-hub.se/https://dl.acm.org/doi/abs/10.1145/3442381.3450056
    * Uses: https://github.com/cavi-au/Consent-O-Matic
* Via TCF: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9152617
* Noyb (https://noyb.eu/en/noyb-aims-end-cookie-banner-terror-and-issues-more-500-gdpr-complaints) don't explain their approach but based on available details (esp. https://wecomply.noyb.eu/en/app/faq#how-can-i-make-my-banner-compliant) likely use CMP-specific adapters, maybe in combination with TCF.
* Privacy policy detection tends to be keyword-based: https://www.ndss-symposium.org/wp-content/uploads/2019/02/ndss2019_04B-2_Degeling_paper.pdf, https://dl.acm.org/doi/pdf/10.1145/3178876.3186087
    * Keyword list: https://github.com/RUB-SysSec/we-value-your-privacy/blob/master/privacy_wording.json
* https://www.open.ou.nl/hjo/supervision/2021-koen-aerts-msc-thesis.pdf and https://pure.tudelft.nl/ws/files/57080768/vaneijk_conpro19.pdf rely on adblock filter lists (like https://secure.fanboy.co.nz/fanboy-cookiemonster.txt), which are _very_ broad, e.g. detecting any element with `CNIL` or `Cookie` in its ID. Manual check revealed error margin of ~15%, interestingly skewed towards false-negatives.

### Observations in Mobile Apps

* Element IDs are sometimes helpful (`de.zalando.prive:id/consent_button_accept_all`) but tend not to be (`com.zhiliao.musically.livewallpaper:id/content_tv`).
* Some consent dialogs are in webviews, Appium does support that be we encountered weird bug whereby you need to issue one `findElements()` call for anything at all before subsequent calls include webview elements.
* Often, apps have something that at first glance looks like a CD but actually just concerns their TOS or similar, not data protection. We will need to filter those out correctly. Note: Even if TOS says something about DP, that doesn't matter legally, so we can safely ignore those cases.

* Different kind of data protection notices, motivating the following taxonomy for this thesis: dialog, notice, link

### Our Approach

* Approach should be automatic, manual at most for validation or small parts.
* As determined in TODO, TCF or CMP-specific approach won't work (only for very few apps), nonetheless we will (additionally) implement TCF stuff for those apps that use it to access more detailed data.
* Few detailed IDs, so filter lists won't work either, too broad anyway.

* Thus: Only option is text-based matching.
* Explain method for differentiating between dialog, notice, link.
* Use keyword score as additional criterion to weed out TOS notices.
* Alternatively: if notice has privacy policy link, that is also sufficient. Unfortunately, also has to be done based on text only, as Appium doesn't support reading link targets.

* Based on manual analysis of apps, list of common phrases and keywords in notices compiled, made into compact regexes that only match on the important words and leave out CD-specific wording as much as possible.
* Main criterion for those: Avoid false-positives! Better to provide under-approximation than to wrongly detect non-CDs as CDs.
* Examples for regexes, full list in Appendix.

### Interaction with Consent Dialogs

## Violation Identification

## Tracking Content Extraction

### Endpoint-Specific Adapters

* Definition of "endpoint"
* Ordered endpoints by how often they were contacted by apps, went through all contacted by at least TODO apps

### Indicator Matching in Network Traffic

## Privacy Labels
