# Analysis Method {#sec:analysis-method}

TODO: Source code available in same repository as instrumentation framework

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

* Different kind of data protection notices, motivating the following taxonomy for this thesis: dialog, notice, link (TODO: explain why)

### Our Approach {#sec:method-our-approach}

* Approach should be automatic, manual at most for validation or small parts.
* As determined in [@sec:cd-situation-mobile], TCF or CMP-specific approach won't work (only for very few apps), nonetheless we will (additionally) implement TCF stuff for those apps that use it to access more detailed data.
* Few detailed IDs, so filter lists won't work either, too broad anyway.

* TODO: Not sure whether this makes sense. Maybe merge the following two paragraphs.
* Thus: Only option is text-based matching.
* Distinction between dialog and notice only through interactive elements. In addition to the criteria for a notice, a dialog needs to have at least one button.
* If an app has neither a dialog nor a notice but we did detect a link to a privacy policy, we classify it as "link".
* Use keyword score as additional criterion to weed out TOS notices.
* Alternatively: if notice has privacy policy link, that is also sufficient. Unfortunately, also has to be done based on text only, as Appium doesn't support reading link targets.

* Based on manual analysis of apps, list of common phrases and keywords in notices compiled, made into compact regexes that only match on the important words and leave out CD-specific wording as much as possible.
* Main criterion for those: Avoid false-positives! Better to provide under-approximation than to wrongly detect non-CDs as CDs.
* One example of a regex to detect typical consent dialog texts:

  ```js
  /have read( and understood)? [^.]{3,35} (privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/
  ```

  Tries to anticipate all possible word choices for "privacy policy" that could come up. As explained before, we leave out any words that aren't strictly necessary to classify a sentence as coming from a consent dialog. We don't care whether a dialog says "You hereby confirm that you have read our aforementioned privacy policy." or simply "I have read the privacy policy." However, it is important that the "have read" and "privacy policy" parts belong to a single statement and aren't parts of entirely separate sentences. Thus, we limit the number of characters that may occur between them and disallow any periods between the parts.
* Full list in Appendix.
* Text matching is done case-insensitively.
* Button and privacy policy link texts need to be at word boundaries, to avoid matching "acknowledge" as "no" for example.
* Appium has no general way of distinguishing between buttons and other elements. Of course, a text element that happens to contain the word "no", shouldn't be detected as a reject button, either. Thus, we additionally only match buttons if their text is at most twice as long as the respective matcher.
* For the keywords, we differentiate between ones that are clearly related to data protection like `/(ad(vertising|s)?|content|experience) personali(s|z)ation/`{.js} or `/(necessary|essential|needed) cookies/`{.js}, which yield one point, and ones that are commonly but not necessarily related to data protection like `'geolocation data'`{.js} or `'IP address'`{.js}, which only yield half a point.
* Even if we don't detect a dialog/notice text, if an app reaches a keyword score of at least 3, we classify it as "maybe dialog/notice".
* Only consider visible elements.

### Interaction with Consent Dialogs

We also interact with the detected consent dialogs to measure the difference in (tracking) behaviour between the app not having received any input vs. after having consented or refused consent. For that, we first reset the app completely and wait ten seconds to allow for the consent dialog to appear.

We then click the first "accept" button we detected, preferring ones with a clear label. As before, we record the network traffic for 60 seconds as before but marking the run as an "accepted" one. After the timeout is over, we also save the preferences of the app.

We repeat the same steps for the "reject" button analogously.

## Violation Identification

TODO: Maybe include a sample screenshot for each violation?

TODO: If we don't detect a violation in a CD, that doesn't mean that it is compliant. They only represent a minimum of compliance that can be reliably checked using automated methods. As such, our findings will only provide a lower bound in terms of violations but, conversely, an upper bound of compliance in mobile apps.

We detect the following violations in apps determined to show a consent dialog:

Processing before consent
:   Processing that can only rely on consent as a legal basis may of course only occur after consent has been given (cf. [@sec:criteria-gdpr]). As such, we consider any tracking (TODO: specify this further?) that happens before we have interacted with a consent dialog or after we have refused consent a violation.

    This also automatically applies to all apps performing without a consent dialog or with only a notice or privacy policy link.

Ambiguous button labels
:   If a consent dialog has an "accept" button, it needs to have a clear label that unambiguously communicates to the user that clicking the button will result in consent to the described processing (cf. [@sec:criteria-buttons]). To detect violations, we sort the button regexes (see [@sec:method-our-approach]) into clear (like "allow" or "consent") and ambiguous (like "okay" or "continue") ones and record a violation if the dialog has at least one ambiguous "accept" button but none with a clear label.

    We proceed analoguously for "reject" buttons, which can also have clear (like "decline" or "refuse") and ambiguous (like "options" or "cancel") labels.

"Accept" button without "reject" button
:   If a consent dialog has an "accept" button on the first layer, it also needs to have a "reject" button on the same layer (cf. [@sec:criteria-buttons]). We record a violation if we detect an "accept" but no "reject" button on the screen shown to the user without any interaction.

"Accept" button highlighted compared to "reject" button by size
:   An app may not nudge a user into consenting by highlighting the "accept" button compared to the "reject" button, for example by making it bigger (cf. [@sec:criteria-design]). To detect violations, we look at the bounding rectangle of both buttons. We record a violation if the product of the "accept" button's width and height is at least 1.5 times bigger than that of the "reject" button. 

    If there is more than one of each button, we can't know which ones to check against each other to detect whether one is highlighted. Thus, for each "accept" button, we only record a violation if _every_ "reject" button is highlighted compared to it. But it is enough if there is one "accept" button that is highlighted, not all of them need to be.

"Accept" button highlighted compared to "reject" button by colour
:   Similarly, a consent dialog may also not have an "accept" button that is more prominent than the "reject" button through its colour (cf. [@sec:criteria-design]). To detect violations, we take screenshots of both buttons (cropped to just the respective button's bounding rectangle). We then use the [`get-image-colors`](https://github.com/colorjs/get-image-colors) library to extract the most prominent color from each screenshot using colour quantisation. Finally, we compute the two colors' deltaE CMC difference [@lindbloomDeltaCMC2017] using the [`chroma.js`](https://vis4.net/chromajs/) library and record a violation if it is more than 30. TODO: Figure of different color differences for reference.

    This of course doesn't guarantee that it's the "accept" and not the "reject" button that's highlighted. To ensure that, we would have to also compare the button color against the background color. Unfortunately, Appium doesn't have the capability to extract the background color and trying to guess which pixels to screenshot to get just the button background without catching other elements would be too error-prone. Thus, we manually review all detected violations of this type.
    
    In the case of more than one of each button type, we proceed exactly as described for the previous violation.

App stops after refusing consent
:   It needs to be possible to use an app without consenting (potentially with a reduced feature set), so an app may not quit after the user has refused their consent (cf. [@sec:criteria-circum]). To detect violations, we first ensure that the app is still running and in the foreground, then click the "reject" button, wait for ten seconds and record a violation if the app is not running and in the foreground anymore afterwards. In the case of multiple "reject" buttons, we click the first one, preferring a "reject" button with clear label, if available.

TODO: US transfers?

## Tracking Content Extraction

### Endpoint-Specific Adapters

* Definition of "endpoint"
* Ordered endpoints by how often they were contacted by apps, went through all contacted by at least TODO apps

### Indicator Matching in Network Traffic

### TODO: Cookies etc.

## Privacy Labels {#sec:method-privacy-labels}
