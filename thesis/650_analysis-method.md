# Analysis Method {#sec:analysis-method}

TODO: Source code available in same repository as instrumentation framework

## Consent Dialog Detection

As it is not feasible to detect consent dialogs on mobile based on the IAB TCF framework or CMP library-specific adapters (see [@sec:cd-situation-mobile]), we need to use an approach that is based on common elements of consent dialogs. Looking at existing research for the web and disregarding TCF- and library-based approaches [@papadogiannakisUserTrackingPostcookie2021b; @matteCookieBannersRespect2020; @noyb.euNoybAimsEnd2021], many approaches for consent dialog detection are purely manual [@sanchez-rolaCanOptOut2019; @trevisanYearsEUCookie2019a; @utzInformedConsentStudying2019a]. Some research relies on adblock filter lists like [*Easylist Cookies*](https://secure.fanboy.co.nz/fanboy-cookiemonster.txt) and [*I don't care about cookies*](https://www.i-dont-care-about-cookies.eu/abp/) to detect HTML elements belonging to consent dialogs based on their ID or class [@aertsCookieDialogsTheir2021; @eijkImpactUserLocation2019a]. These lists are _very_ broad, e.g. detecting any element with `CNIL` (the French data protection authority) or `Cookie` in its ID. Finally, privacy policy detection tends to be keyword-based [@libertAutomatedApproachAuditing2018; @degelingWeValueYour2019], matching on general terms like "policy" and "GDPR"^[See: <https://github.com/RUB-SysSec/we-value-your-privacy/blob/181cbffb62ce2dcc89ff9b467401093aa10f0cd8/privacy_wording.json>], or use natural language processing [@hosseiniUnifyingPrivacyPolicy2021].

The approach we use for our analysis should be automatic, with manual steps required at most for validation. We found that while some elements in mobile apps have descriptive IDs (e.g. `de.zalando.prive:id/consent_button_accept_all`), this is not as common on the web, with most elements IDs not containing enough information to discern whether they contain a consent dialog (e.g. `com.zhiliao.musically.livewallpaper:id/content_tv` does contain one). This means that we cannot rely on element IDs alone and won't be able to use adblock filter lists. The ones described for the web are too broad anyway. We found many apps displaying a dialog that at first glance looks like a consent dialog but actually just concerns the company's terms of service or similar. These need to be filtered out correctly^[Even if those apps bury data protection information somewhere in their terms of service, it doesn't make a terms of service dialog into a consent dialog, so we can safely ignore those cases.].

Based on those considerations, we use a text-based approach that matches on the elements' text content. We encountered three main types of apps referencing data protection, which we want to distinguish, motivating the following taxonomy for this thesis:

Link
:   Some apps only contain a link to a privacy policy in a menu or the footer. While this can be enough to satisfy a controller's information obligations under Art. 12–14 GDPR, a link can obviously not be used to obtain consent from a user.

Notice
:   Some apps inform users that the app processes their data, not seldom claiming that the users agrees to this by continuing to use the app. The notices are often in the form of a banner or a short sentence tucked away under a form. As established in [@sec:critera], consent in the context of data protection cannot be given through inaction, so apps may not assume consent based on only such a notice. It can however be used by the controller to meet their duty to inform the user of the processing.

Dialog
:   Finally, some apps not only inform the user about their data processing but actively solicit their consent through a button or a checkbox that needs to be clicked. This is the only way that apps can actually obtain valid consent under the GDPR.

### Our Approach {#sec:method-our-approach}

Based on manually looking at many apps, we have collected a list of common phrases that German and English apps use to refer to data protection like "we care about your privacy" or "by continuing to use our app, you acknowledge that we may process your data in line with out data protection statement". We extracted the key elements from these phrases and compiled them into compact regexes that only match on the important words, leaving out as much of the app-specific wording as possible.

We detect a dialog or notice in an app if we encounter at least one match for one of those regexes in an element. We distinguish between notices and dialogs only by whether they contain an interactive element. In addition to the criteria for a notice, a dialog also needs to have at least one button. For that, we have compiled another list of regexes for buttons typically found in consent dialogs, matching on labels like "accept", "okay", or "reject".  
If an app has neither a dialog nor a notice but we detect a link to a privacy policy, we classify it as "link". Unfortunately, search for privacy policy links also has to be done based on text only, as Appium doesn't support reading link targets.

To weed out notices and dialogs not referring to data protection, we introduce another criterion: We have compiled a list of keywords commonly found in consent dialogs and assign a keyword score based on how many of those we find in an app. We differentiate between keywords that are clearly related to data protection like `/(ad(vertising|s)?|content|experience) personali(s|z)ation/`{.js} or `/(necessary|essential|needed) cookies/`{.js}, which yield one point, and ones that are commonly but not necessarily related to data protection like `'geolocation data'`{.js} or `'IP address'`{.js}, which only yield half a point.  
We only detect a dialog or notice if the keyword score is at least one. Alternatively, if we find a privacy policy link, that is also sufficient. Conversely, even if we don't detect one of the dialog phrases, if an app reaches a keyword score of at least three, we classify it as "maybe dialog/notice".

One of those phrase regexes looks like this for example:

```js
/have read( and understood)? [^.]{3,35}
    (privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/
```

This regex tries to anticipate all possible word choices for "privacy policy" that could come up. As explained, we leave out any words that aren't strictly necessary to classify a sentence as coming from a consent dialog. For our purposes, it isn't important whether a dialog says "You hereby confirm that you have read our aforementioned privacy policy." or simply "I have read the privacy policy." However, it is important that the "read" and "privacy policy" parts belong to a single statement and aren't parts of entirely separate sentences. Thus, we limit the number of characters that may occur between them and disallow periods between the parts.  
The main criterion when compiling the regexes was to avoid false-positives under the assumption that it is better to provide an under-approximation of consent dialog prevalence than to wrongly detect other elements as consent dialogs. A full list of the regexes we used can be found in Appendix TODO.

All text matching is done case-insensitively. We only consider visible elements. Button and privacy policy link texts additionally need to be at word boundaries, to avoid matching "acknowledge" as "no" for example.  
Appium has no general way of distinguishing between buttons and other elements. Of course, a text element that happens to contain the word "no", shouldn't be detected as a reject button, either. Thus, we additionally only match buttons if their text is at most twice as long as the respective matcher.

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

## Analysis of IAB TCF data

Even though only comparatively few apps implement the IAB TCF (cf. [@sec:cd-situation-mobile]), we nonetheless analyse the TCF data for those apps that do use it in addition to the approach described above to leverage the more detailed data.

## Tracking Content Extraction

### Endpoint-Specific Adapters

* Definition of "endpoint"
* Ordered endpoints by how often they were contacted by apps, went through all contacted by at least TODO apps

### Indicator Matching in Network Traffic

### TODO: Cookies etc.

## Privacy Labels {#sec:method-privacy-labels}
