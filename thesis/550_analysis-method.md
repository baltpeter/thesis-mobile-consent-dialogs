# Analysis Method {#sec:analysis-method}

In this chapter, we present our method for detecting consent dialogs and violations in them, as well as how we extract the actual data being transmitted in the recorded traffic. TODO: General steps for analysis, maybe even as a diagram?

The source code is available in the same repository as the device instrumentation framework.


## Consent Dialog Detection

As it is not feasible to detect consent dialogs on mobile based on the IAB TCF framework or CMP library-specific adapters (see [@sec:cd-situation-mobile]), we need to use an approach that is based on common elements of consent dialogs. Looking at existing research for the web and disregarding TCF- and library-based approaches [@papadogiannakisUserTrackingPostcookie2021b; @matteCookieBannersRespect2020; @nouwensDarkPatternsGDPR2020; @noyb.euNoybAimsEnd2021], most approaches for consent dialog detection are purely manual [@sanchez-rolaCanOptOut2019; @trevisanYearsEUCookie2019a; @utzInformedConsentStudying2019a; @mehrnezhadCrossPlatformEvaluationPrivacy2020]. Some research relies on adblock filter lists like [*Easylist Cookies*](https://secure.fanboy.co.nz/fanboy-cookiemonster.txt) and [*I don't care about cookies*](https://www.i-dont-care-about-cookies.eu/abp/) to detect HTML elements belonging to consent dialogs based on their ID or class [@aertsCookieDialogsTheir2021; @eijkImpactUserLocation2019a]. These lists are _very_ broad, e.g. detecting any element with `CNIL` (the French data protection authority) or `Cookie` in its ID. Finally, privacy policy detection tends to be keyword-based [@libertAutomatedApproachAuditing2018; @degelingWeValueYour2019], matching on general terms like "policy" and "GDPR"^[See: <https://github.com/RUB-SysSec/we-value-your-privacy/blob/181cbffb62ce2dcc89ff9b467401093aa10f0cd8/privacy_wording.json>], or use natural language processing [@hosseiniUnifyingPrivacyPolicy2021].

The approach we use for our analysis should be automatic, with manual steps required at most for validation. We found that while some elements in mobile apps have descriptive IDs (e.g. `de.zalando.prive:id/consent_button_accept_all`), this is not as common on the web, with most elements IDs not containing enough information to discern whether they contain a consent dialog (e.g. `com.zhiliao.musically.livewallpaper:id/content_tv` does contain one). This means that we cannot rely on element IDs alone and won't be able to use adblock filter lists (the described ones for the web are too broad anyway).  
We found many apps displaying a dialog that at first glance looks like a consent dialog but actually just concerns the company's terms of service or similar. These need to be filtered out correctly^[Even if those apps bury data protection information somewhere in their terms of service, it doesn't make a terms of service dialog into a consent dialog (cf. Article 7(2) GDPR), so we can safely ignore those cases.].

Based on those considerations, we use a text-based approach that matches on the elements' text content. We encountered three main types of apps referencing data protection, which we want to distinguish, motivating the following taxonomy for this thesis:

Link
:   Some apps only contain a link to a privacy policy in a menu or the footer. While this can be enough to satisfy a controller's information obligations under Articles 12–14 GDPR, a link can obviously not be used to obtain consent from a user.

Notice
:   Some apps inform users that the app processes their data, not seldom claiming that the user agrees to this by continuing to use the app. The notices are often in the form of a banner or a short sentence tucked away under a form. As established in [@Sec:critera], consent in the context of data protection cannot be given through inaction, so apps may not assume consent based on only such a notice. It can however be used by the controller to meet their duty to inform the user of the processing.

Dialog
:   Finally, some apps not only inform the user about their data processing but actively solicit their consent through a button or a checkbox that needs to be clicked. This is the only way that apps can actually obtain valid consent under the GDPR.

### Our Approach {#sec:method-our-approach}

Based on manually looking at many apps, we have collected a list of common phrases that German and English apps use to refer to data protection, like "we care about your privacy" or "by continuing to use our app, you acknowledge that we may process your data in line with our data protection statement". We extracted the key elements from these phrases and compiled them into compact regexes that only match on the important words, leaving out as much of the app-specific wording as possible.

We detect a dialog or notice in an app if we encounter at least one match for one of those regexes in an element. We distinguish between notices and dialogs only by whether they contain an interactive element: In addition to the criteria for a notice, a dialog also needs to have at least one button. For that, we have compiled another list of regexes for buttons typically found in consent dialogs, matching on labels like "accept", "okay", or "reject".  
If an app has neither a dialog nor a notice but we detect a link to a privacy policy, we classify it as "link". Unfortunately, searching for privacy policy links also has to be done based on text only, as Appium doesn't support reading link targets.

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
Appium has no general way of distinguishing between buttons and other elements. Of course, a text element that happens to contain the word "no" shouldn't be detected as a reject button, either. Thus, we additionally only match buttons if their text is at most twice as long as the respective matcher.

TODO: Negator regexes

### Interaction with Consent Dialogs

We also interact with the detected consent dialogs to measure the difference in (tracking) behaviour between the app not having received any input and after having consented or refused consent. For that, we first reset the app completely and wait ten seconds to allow for the consent dialog to appear.

We then click the first "accept" button we detected, preferring ones with a clear label. As before, we record the network traffic for 60 seconds but mark the run as an "accepted" one. After the timeout is over, we also save the preferences of the app.

We repeat the same steps for the "reject" button analogously.

## Dark Pattern Identification

TODO: Maybe include a sample screenshot for some.

We detect the following violations and dark patterns in apps determined to show a consent dialog:

Processing before consent
:   Processing that can only rely on consent as a legal basis may of course only occur after consent has been given (cf. [@sec:criteria-gdpr]). As such, we consider any tracking that happens before we have interacted with a consent dialog or after we have refused consent a violation.

    This also automatically applies to all apps performing tracking without a consent dialog or with only a notice or privacy policy link.

Ambiguous button labels
:   If a consent dialog has an "accept" button, it needs to have a clear label that unambiguously communicates to the user that clicking the button will result in consent to the described processing (cf. [@sec:criteria-buttons]). To detect violations, we sort the button regexes (see [@sec:method-our-approach]) into clear (like "allow" or "consent") and ambiguous (like "okay" or "continue") ones and record a violation if the dialog has at least one ambiguous "accept" button but none with a clear label.

    We proceed analoguously for "reject" buttons, which can also have clear (like "decline" or "refuse") and ambiguous (like "options" or "cancel") labels.

"Accept" button without "reject" button
:   If a consent dialog has an "accept" button on the first layer, it also needs to have a "reject" button on the same layer (cf. [@sec:criteria-buttons]). We record a violation if we detect an "accept" but no "reject" button on the screen shown to the user without any interaction.

"Accept" button highlighted compared to "reject" button by size
:   An app may not nudge a user into consenting by highlighting the "accept" button compared to the "reject" button, for example by making it bigger (cf. [@sec:criteria-design]). To detect violations, we look at the bounding rectangle of both buttons. We record a violation if the product of the "accept" button's width and height is at least 1.5 times bigger than that of the "reject" button. 

    If there is more than one of each button, we can't know which ones to check against each other to detect whether one is highlighted. Thus, for each "reject" button, we only record a violation if _every_ "accept" button is highlighted compared to it. But it is enough if there is one "accept" button that is highlighted, not all of them need to be.

"Accept" button highlighted compared to "reject" button by colour
:   Similarly, a consent dialog may also not have an "accept" button that is more prominent than the "reject" button through its colour (cf. [@sec:criteria-design]). To detect violations, we take screenshots of both buttons (cropped to just the respective button's bounding rectangle). We then use the [`get-image-colors`](https://github.com/colorjs/get-image-colors) library to extract the most prominent colour from each screenshot using colour quantisation. Finally, we compute the two colours' deltaE CMC difference [@lindbloomDeltaCMC2017] using the [`chroma.js`](https://vis4.net/chromajs/) library and record a violation if it is more than 30. TODO: Figure of different colour differences for reference.

    This of course does not guarantee that it's the "accept" and not the "reject" button that's highlighted. To ensure that, we would have to also compare the button colour against the background colour. Unfortunately, Appium doesn't have the capability to extract the background colour and trying to guess which pixels to screenshot to get just the button background without catching other elements would be too error-prone. Thus, we manually review all detected violations of this type.
    
    In the case of more than one of each button type, we proceed exactly as described for the previous violation.

App stops after refusing consent
:   It needs to be possible to use an app without consenting (potentially with a reduced feature set), so an app may not quit after the user has refused their consent (cf. [@sec:criteria-circum]). To detect violations, we first ensure that the app is still running and in the foreground, then click the "reject" button, wait for ten seconds and record a violation if the app is not running and in the foreground anymore afterwards. In the case of multiple "reject" buttons, we click the first one, preferring a "reject" button with clear label, if available.

Even if we don't detect a violation or dark pattern in a consent dialog, that doesn't mean that it is compliant. An absence of violations only represents a minimum of compliance that can be reliably checked using automated methods. As such, our findings will only provide a lower bound in terms of violations but, conversely, an upper bound of compliance in mobile apps.

## Tracking Content Extraction

To extract and classify the tracking data that apps send from the recorded network traffic, we use a two-fold approach: We wrote a series of adapters for the most common trackers which understand the actual tracking protocol and can thus precisely extract the transmitted data. For those requests that are not matched by one of our adapters, we employ indicator matching to check for the presence of common data types. For each request, we decide whether the contained data is pseudonymous or anonymous. We consider the data in a request pseudonymous if the request contains at least one unique identifier for the device or user like the device's advertising ID (including the IDFV on iOS and hashed forms thereof) or the user's public IP address^[It is of course not technically possible for a server to handle a user's request without at least temporarily processing their IP address. We only consider cases where the IP address is literally included in the request body or path.]. Otherwise, we consider the data in the request anonymous.

In addition to that, we also analyse that cookies that are set in requests. For that, we leverage the Open Cookie Database [@kwakmanOpenCookieDatabase2022], a list of 710 cookies as of the time of writing, mapped to the platform they are set by and a category they can be attributed to, among other things.

### Endpoint-Specific Tracking Request Adapters

We noticed that there is a comparatively small number of tracking endpoints which make up a large portion of the app traffic. We developed 26 adapters than can extract the tracking data in a common schema that we can easily reason about for the most common endpoints. For our purposes, an endpoint is uniquely identified by the scheme, host and path without GET parameters.

Each adapter consists of these parts:

Endpoint URLs
:   Each adapter has a list of endpoints that it works for. Endpoints can either be specified as simple strings or as regexes to accomodate for URLs with parameters in hostname or path.

Match function
:   Optionally, adapters can have an additional match function that is used to filter out requests to the same endpoint that the adapter cannot handle, e.g. based on the request method or body.

Prepare function
:   Tracking data can be included in the URL or request body. In addition, we have observed a variety of data formats and encodings used by trackers, sometimes even different ones for the same endpoint. The prepare function parses as much as possible of the raw request into a JavaScript object with plain text values.

    Steps of the processing that needs to happen in the prepare function include: Parsing JSON or query strings, decoding Protobuf blobs, combining data from the body and GET parameters, and decoding base64 strings. Often, different formats and encodings are nested. For example, the bodies of requests to Supersonic can either be a plain JSON object or a base64 string that holds a GZIP which in turns holds the actual JSON object. Meanwhile, ironSource sends a base64-encoded JSON as a query string parameter. And some requests to Facebook have a query string as the body which holds a JSON with one property being an array of events that itself a JSON string, while others have a JSON object as the body that holds a JSON string of an array of objects where the actual data is query-string-encoded in each object's value.

Extract function
:   Finally, the extract function extracts the known data types from the prepared request and brings it into a unified schema. In many cases, one data type can be present in one of a list of properties, so we use the first one that actually holds data.

    Sometimes, it is not obvious which data a property holds because it has no name or the name is not descriptive. In these cases, we looked at all instances of the respective property across all requests and only extracted the properties we were able to definitively identify. This means that we can once again only provide a lower bound on the data that is being transmitted.

### Indicator Matching in Network Traffic

For the requests that cannot be handled by any of our endpoint-specific adapters, we perform indicator matching on the path and request body. We search for the Honey data values described in [@sec:instrumentation-honey-data].

In addition to matching against the plain text, we also match base64-encoded values. This cannot be done by simply encoding the indicator value and matching the traffic against that. The actual base64 encoding of a value depends on its offset within the whole string that is being encoded as well as the string's length. We ported a PowerShell script [@holmesSearchingContentBase642017] that generates all possible ways a value can be base64-encoded and builds a regex for that to JavaScript^[We have published our port as a library: <https://github.com/baltpeter/base64-search>].

## Apple Privacy Labels {#sec:method-privacy-labels}

App developers on iOS are supposed to inform users about what data their apps process. Among other things, they need to declare the following two things [@appleinc.AppPrivacyDetails2021]:

Types of data
:   The privacy label needs to list the data types collected by the app, regardless of whether they are collected by the app developer themselves or by third-party companies. As of the time of writing, there are 32 possible data types across 14 categories. While the meaning of some data types is obvious, e.g. for "email address" and "phone number", others are not well defined and lack a clear description, e.g. "Other Data Types" which is simply described as "[a]ny other data types not mentioned".

    The data types have to be sorted into "Data Linked to You", "Data Used to Track You", and "Data Not Linked to You". If an app doesn't collect any data, it can declare an empty "Data Not Collected" list.

Purposes
:   In addition, the privacy label needs to list the purposes that the data types are collected for. The possible values as of the time of writing are: "Third-Party Advertising", "Developer’s Advertising or Marketing", "Analytics", "Product Personalization", "App Functionality", and "Other Purposes".

To analyse the privacy labels, for each app, we go through the privacy types and record a list of the data types and purposes declared in the label, distinguishing between ones declared as pseudonymous (i.e. with a privacy type of "Data Linked to You" or "Data Used to Track You") and anonymous (i.e. with a privacy type of "Data Not Linked to You"). 

Then, we look at the detected tracking content as described in the previous section. We compare the data types that we observed being transmitted by the app against the data types declared in the label. As some of the possible data types in privacy labels are not clearly defined, we have created a mapping between them and the data types we detect, which can be seen in [@tbl:method-privacy-label-mapping]. We can only check a subset of the data types that can be declared. For each privacy label data type, we determine whether it was correctly declared, correctly not declared, wrongly declared as anonymous, wrongly undeclared, unnecessarily declared, or unnecessarily declared as pseudonymous. Of course, detections of unnecessarily declarations or a correct lacks of a declaration are only within the context of the traffic we recorded. It is possible that apps do in fact transmit this data but we did not observe that.

| Privacy label data type | Our corresponding data types                                                                                                           |
|-|--|
| Email Address           | Apple ID email address                                                                                                                 |
| Phone number            | Phone number                                                                                                                           |
| Health                  | Apple Health honey data                                                                                                                |
| Location                | Coordinates or address of device location                                                                                              |
| Contacts                | Contacts honey data                                                                                                                    |
| Emails or Text Messages | SMS honey data                                                                                                                         |
| Other User Content      | Clipboard content, honey data in reminders, calendar, notes, and Apple Home                                                            |
| Product Interaction     | Viewed pages in the app, whether the app is in the foreground                                                                          |
| Performance Data        | RAM usage, disk usage, device uptime                                                                                                   |
| Device ID               | IDFA, IDFV, hashed IDFA, hashed IDFV                                                                                                   |
| Other Diagnostic Data   | Device root status, device emulator status, network connection type, signal strength, charging status, battery percentage, sensor data |
| Other Data Types        | Device name, carrier, roaming status, local IP address(es), MAC address(es), BSSID, volume                                             |

:   Mapping from data types that can appear in privacy labels [@appleinc.AppPrivacyDetails2021] to the data types that we detect and consider to be equivalent. Note that unlike Apple we do not distinguish between precise and coarse location. {#tbl:method-privacy-label-mapping}

Finally, we look at the declared purposes. Here, we judge whether the app correctly declares the purposes "Analytics" and "Third-Party Advertising"/"Developer’s Advertising or Marketing". We do this by comparing the contacted hosts against the EasyList and EasyPrivacy adblock filter lists^[As EasyList and EasyPrivacy are meant for adblockers in browsers, they contain a lot more than hostnames, e.g. HTML element selectors. We can however only check the contacted domains and thus use the Firebog versions of both lists, which are meant for Pi-hole, a network-wide adblocker at the DNS level, and only contain hostnames [@wally3kBigBlocklistCollection2022]: <https://v.firebog.net/hosts/Easylist.txt> and <https://v.firebog.net/hosts/Easyprivacy.txt>] [@theeasylistauthorsEasyListOverview2021].
