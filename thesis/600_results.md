# Results

We successfully analysed 4388 apps with 2068 apps on Android and 2320 apps on iOS, corresponding to 62.42&nbsp;% and 93.51&nbsp;% of the downloaded apps, respectively. On Android, the high number of apps we could not analyse is caused for the most part by problems with the certificate pinning bypass through objection. 1049 of the Android apps failed to launch or quit immediately after being launched through objection. These apps were excluded from the analysis. We discuss this further in [@sec:discussion-limitations]. On iOS, only 65 apps failed to launch and 18 apps could not be installed because they require a newer version of iOS than we can use. The remaining failures on both platforms were mostly due to Appium or Frida commands failing even after multiple retries. 
<!-- select count(1) from dialogs;
select count(1) from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app where a.platform = 'android';
select count(1) from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app where a.platform = 'ios'; -->

To promote reproducability, the processed data behind all graphs is available in our GitHub repository.

## Network Traffic and Tracking

\begin{figure}[h]
\hypertarget{fig:results-requests-hosts-per-app}{%
\centering
\includegraphics{../graphs/requests_hosts_per_app.pdf}
\caption{Number of requests and unique hosts contacted per app without any user interaction. Three apps with more than 1000 requests are omitted in this graph: \texttt{com.prequel.app} on Android with 2500 requests, and \texttt{com.audiomack.iphone} and \texttt{com.storycover} on iOS with 2383 and 1019 requests, respectively.}\label{fig:results-requests-hosts-per-app}
}
\end{figure}

In total, we recorded 194817 requests after filtering out the operating systems' background traffic. [@Fig:results-requests-hosts-per-app] illustrates the amount of requests and unique hosts per app in the initial run before we interacted with the apps. 50&nbsp;% of apps did less than 23 requests and 75&nbsp;% of apps did less than 50 requests but there were also some outliers with up to 2500 requests from a single app and 19 apps doing more than 500 requests. On average, apps on Android did 44.27 requests and apps on iOS did 44.66 requests. There were 65 apps on Android and 158 apps on iOS with no requests at all.  
53&nbsp;% of apps contacted less than 10 unique hosts, with 11.85 hosts on average across both platforms.
<!-- select c.platform, avg(c.count) from (select count(1) count, platform from filtered_requests where run_type='initial' group by name, version, platform) as c group by c.platform; -->
<!-- Excel:
     H7=COUNT($D$2:$D$4164)
     H8=COUNTIF($D$2:$D$4164, "<50")
     H9=H8/H7 -->
<!-- select count(1) from apps where platform='ios' and not exists(select 1 from filtered_requests fr where fr.name=apps.name and fr.version=apps.version and fr.platform=apps.platform); -->
<!-- select count(1) from apps where platform='android' and not exists(select 1 from filtered_requests fr where fr.name=apps.name and fr.version=apps.version and fr.platform=apps.platform); -->
<!-- Excel:
     I7=COUNT($E$2:$E$4164)
     I8=COUNTIF($E$2:$E$4164, "<10")
     I9=I8/I7 -->
<!-- select avg(c.host_count) from (select count(distinct host) host_count, platform from filtered_requests where run_type='initial' group by name, version, platform) as c; -->

\begin{figure}[H]
\hypertarget{fig:results-exodus-tracker-counts}{%
\centering
\includegraphics{../graphs/exodus_tracker_counts.pdf}
\caption{Number of apps that sent requests to the 25 most common
trackers in our dataset according to Exodus
\protect\hyperlink{ref-exoduscontributorsExodusTrackerInvestigation2022}{{[}149{]}}
(without user interaction). The trackers are coloured by the country
they are based in. We compiled the mapping from tracker to country by
looking at the trackers' privacy policies. When a policy listed multiple
establishments, we chose the country of the main
one.}\label{fig:results-exodus-tracker-counts}
}
\end{figure}

61700 (33.32&nbsp;%) of the requests that happened without user interaction were identified as going to trackers when we compared their hostnames against the Exodus tracker database [@exoduscontributorsExodusTrackerInvestigation2022], with 78.08&nbsp;% of apps making at least one request to a tracker. [@Fig:results-exodus-tracker-counts] shows the 25 most common tracker companies that we encountered. Google and Facebook were the most common tracker companies by far, receiving traffic from 70.35&nbsp;% and 31.29&nbsp;% of apps, respectively. Notably, Google's trackers were the most common across Android _and_ iOS. On Android, 81.21&nbsp;% of apps sent traffic to Google trackers, and on iOS, 67.11&nbsp;% did. The remaining trackers were all only contacted by 10&nbsp;% or less of the apps. The majority of the contacted trackers are in the US, with only six of the 25 most common trackers being based in different countries, namely Israel, Singapore, China, and Russia.
<!-- select platform, count(distinct name) from filtered_requests where host ~
      '2mdn\.net|\.google\.com|dmtry\.com|doubleclick\.com|doubleclick\.net|mng-ads\.com|\.google\.com|google-analytics\.com|crashlytics\.com|2mdn\.net|dmtry\.com|doubleclick\.com|doubleclick\.net|mng-ads\.com|firebase\.com|www\.googletagmanager\.com|www\.googletagservices\.com|app-measurement\.com|googlesyndication\.com'
    group by platform; -->

![Number of times that the observed data types were transmitted per app and tracker without any user interaction, grouped by whether they were transmitted linked to a unique device ID (i.e. pseudonymously) or without identifiers for the device (i.e. anonymously). Note that we are also using the term "IDFA" for the Android advertising ID here.](../graphs/data_type_transmissions_initial.pdf){#fig:results-data-type-transmissions-initial}

Looking at the data transmitted to trackers, 3201 apps (72.95&nbsp;%) sent a request containing a unique device identifier like the advertising ID, IDFV, or another UUID in the initial run, making all other data included in those requests pseudonymous and thus personal data that falls under the GDPR. Our 26 endpoint-specific tracking request adapters were enough to process 20465 of 194817 requests (10.50&nbsp;%). Using those and indicator matching on the requests not covered by an adapter, we also observed a wide array of other data types being transmitted to trackers, including for example the location, jailbreak status, volume, battery percentage, sensor data, and disk usage. [@Fig:results-data-type-transmissions-initial] lists how often each data type was transmitted per app and tracker. Indeed, even benign data types like the operating system or phone model are linked to the specific user and device through unique IDs in most cases.

```{=latex}
\afterpage{%
    \clearpage% Flush earlier floats (otherwise order might not be correct)
    \begin{landscape}
```

![Observed transmissions of various types of data to trackers without interaction, grouped by platform. Note that we are also using the term "IDFA" for the Android advertising ID here. Each point represents a number of apps transmitting the respective row's data type to the tracker in the respective column, with the size of the point indicating how many apps performed this transmission at least once. The points are coloured according to the apps' platform.\
\
The observations in the "\<indicators>" column came from string-matching plain and base64-encoded text in the requests not covered by an endpoint-specific tracking request adapter.](../graphs/apps_trackers_data_types_initial.pdf){#fig:results-tracker-data-initial}

```{=latex}
    \end{landscape}
    \clearpage% Flush page
}
```

[@Fig:results-tracker-data-initial] further plots the observed data types against the trackers they were sent to, highlighting that some trackers are only active on one platform and others transmit different types of data depending on the platform. For example, we saw Facebook receiving significantly fewer data types on iOS compared to Android. Conversely, Google Firebase received more data types on iOS.  
From this data, we can also infer that some trackers are more common on one platform. For example, we observed significantly more transmissions to AdColony on Android compared to iOS, while it is the other way around for ioam.de and ironSource.

![Prevalence of cookies by various companies and which category they can be attributed to (across all runs) according to [@kwakmanOpenCookieDatabase2022]. Each point represents the number of times a cookie by the company in the respective row and belonging to the category in the respective column was set by an app to a different value, with the size of the point indicating how often the cookie was set. The points are coloured according the apps' platform.](../graphs/cookies.pdf){#fig:results-cookies}

Finally, we also analysed the cookies that were set in the requests against the Open Cookie Database. The results are shown in [@Fig:results-cookies]. We only observed cookies from the *Analytics* and *Marketing* categories but none from the *Functional* and *Preferences* categories, which is likely due to the database's focus on websites. Most cookies we saw were marketing cookies. We saw a more diverse set of companies setting cookies on Android than on iOS. Once again, Google was the most prevalent company on both platforms.

## Prevalence of Consent Dialogs

---------------------------------------------------------
Classification     Detections    Detections    Detections
                   on Android        on iOS      in total
--------------- ------------- ------------- -------------
dialog                    132           199           331
                     (6.38 %)      (8.58 %)      (7.54 %)

maybe dialog               17            36            53
                     (0.82 %)      (1.55 %)      (1.21 %)

notice                    103            82           185
                     (4.98 %)      (3.53 %)      (4.22 %)

maybe notice                5             5            10
                     (0.24 %)      (0.22 %)      (0.23 %)

link                      103           103           206
                     (4.98 %)      (4.44 %)      (4.69 %)

neither                  1708          1895          3603
                    (82.59 %)     (81.68 %)     (82.11 %)
---------------------------------------------------------

:   Number of apps where the different consent elements were detected by platform. The percentages are relative to all apps in the respective column. {#tbl:results-cd-prevalence}

[@Tbl:results-cd-prevalence] lists the number of apps where our analysis detected a consent element. Across all apps, we detected a consent dialog in 384 apps (8.75&nbsp;%), a consent notice in 195 apps (4.44&nbsp;%), and a link to a privacy policy in 206 apps (4.69&nbsp;%). Thus, in total, 785 apps (17.89&nbsp;%) had one of the consent elements we detect.

There appears to be little difference in the prevalence of the consent elements between platforms. Across all types, the relative counts differ by no more than 2.3 percentage points. We detected slightly more consent dialogs on iOS compared to Android, whereas we detected slightly more notices on Android. In total, we detected any consent element in 18.32&nbsp;% of apps on iOS compared to 17.41&nbsp;% on Android.

## Violations in Consent Dialogs

```{=latex}
\afterpage{%
    \clearpage% Flush earlier floats (otherwise order might not be correct)
    \begin{landscape}
```

![UpSet plot [@lexUpSetVisualizationIntersecting2014] showing the different combinations of dark patterns we have detected in consent dialogs. Note that not all combinations are possible. Most of the dark patterns refer to the "reject" button and thus of course cannot occur if there was no "reject" button to begin with.\
\
The upper violin plot illustrates the distribution of top chart positions among the apps in the respective set. If an app was listed in multiple top charts, we recorded its highest position.](../graphs/dialog_dark_patterns.pdf){#fig:results-dialog-dark-patterns}

```{=latex}
    \end{landscape}
    \clearpage% Flush page
}
```

Looking at the individual dark patterns, 43.2&nbsp;% of the dialogs did not have a "reject" button on the first layer. Ambiguous labels for the "accept" and "reject" buttons were also common with 37.5&nbsp;% and 32.8&nbsp;% of dialogs exhibiting them, respectively. "Accept" buttons were most commonly highlighted compared to "reject" buttons by colour with 31.2&nbsp;% of dialogs compared to only 10.7&nbsp;% of dialogs highlighting the "accept" button by size. Finally, 16 apps (4.2&nbsp;%) quit after refusing consent.

[@Fig:results-dialog-dark-patterns] illustrates the observed combinations of dark patterns in consent dialogs and compares them against the apps' top chart positions. We most commonly observed "accept" buttons with an ambiguous label in combination with no "reject" button on the first layer (22.7&nbsp;% of dialogs). Consent dialogs also often have an ambiguous "reject" button and highlight the "accept" button by colour (14.3&nbsp;%). Both of those were slightly more frequently the case for apps ranked highly in the top charts. Other than that, most dark patterns ocurred on their own and with no significant correlation to the apps' top chart position.

In total, we have detected at least one dark pattern in 347 of the 384 apps with a dialog (90.36&nbsp;%). The share of dark patterns in dialogs is slightly higher on Android with 136 of 149 dialogs (91.28&nbsp;%) compared to 211 of 235 (89.79&nbsp;%) on iOS.

On their own, the dark patterns we detect are not necessarily violations of data protection law. Using dark patterns in a consent dialog just results in the consent acquired through it being invalid. As such, the actual violation that we can detect is the transmission of tracking data based on such invalid consent^[Though presenting the user with a consent dialog that uses dark patterns without ever actually requiring consent for any processing would arguably run afoul of the principle of lawfulness, fairness, and transparency set forth by Article 5(1)(a) GDPR and thus be a violation in and of itself.].

We found that 328 of the 384 apps with a dialog (85.42&nbsp;%) transmitted pseudonymous data in any of our runs. Further, 297 of the 347 apps with a detected dark pattern in their dialog (85.59&nbsp;%) transmitted pseudonymous data in any of our runs. Taking that into consideration, we have identified that 77.34&nbsp;% of the 384 detected dialogs failed to acquire valid consent for the tracking that they perform.

## Effect of User Choices

To gain insights into how different choices in the consent dialogs affect the tracking going on, we collected the app's network traffic, distinguishing between the initial run without any user input, and the runs after accepting and rejecting the dialog if present. We collected traffic for 330 apps after accepting and 28 apps after rejecting. The latter number might seem low but can be explained by the fact that most dialogs we found either did not contain a first-layer "reject" button at all or only had one with an ambiguous label and we only clicked ones with a clear label.  
We collected 185152 requests in the initial runs, 9342 requests in the accepted runs, and 323 requests in the rejected runs. Note that for the accepted and rejected runs, we only collected the traffic _after_ clicking the respective button. The initial traffic before any interaction was not recorded again in those runs to only capture the change in traffic after interaction.  
Given the low number of apps for which we were able to collect traffic after rejecting and the low number of corresponding requests, the results for those are most likely not representative.
<!-- select count(1) from runs where run_type='accepted'; -->
<!-- select count(1) from runs where run_type='rejected'; -->
<!-- select count(1) from filtered_requests where run_type = 'initial'; -->
<!-- select count(1) from filtered_requests where run_type = 'accepted'; -->
<!-- select count(1) from filtered_requests where run_type = 'rejected'; -->

In the traffic before interaction, 33.32&nbsp;% of requests were identified as trackers by Exodus. In the traffic after accepting the dialogs, this percentage slightly dropped to 31.90&nbsp;%, while after rejecting, there was actually a higher percentage of the traffic that was identified as tracking with 47.06&nbsp;%. Meanwhile, 78.08&nbsp;% of apps contacted at least one Exodus-identified tracker in the initial runs. In the accepted runs, 25 additional apps (7.58&nbsp;% of the accepted apps) contacted a tracker that previously didn't. In the rejected runs, 16 of 28 apps (57.14&nbsp;%) continued contacting trackers, as did one additional app for the first time.

Furthermore, in the initial runs, 3201 of the 4388 apps (72.95&nbsp;%) transmitted pseudonymous data. Of the 384 apps with a detected dialog, 282 (73.44&nbsp;%) already transmitted pseudonymous data before receiving a consent choice. In the accepted runs, 46 additional apps started transmitting pseudonymous data. In the rejected runs, 12 of 28 apps (42.85&nbsp;%) continued transmitting pseudonymous data and one app started doing so for the first time.

![Number of times that the observed data types were transmitted per app and tracker after accepting the consent dialogs, grouped by whether they were transmitted linked to a unique device ID (i.e. pseudonymously) or without identifiers for the device (i.e. anonymously). Note that we are also using the term "IDFA" for the Android advertising ID here.](../graphs/data_type_transmissions_accepted.pdf){#fig:results-data-type-transmissions-accepted}

[@Fig:results-data-type-transmissions-accepted] lists how often each data type was transmitted per app and tracker after accepting. Comparing that to the transmissions without user interaction in [@fig:results-data-type-transmissions-initial] shows little difference in the data types that are transmitted to trackers after consent was given.

## Apple Privacy Labels

112 of the 2481 apps on iOS (4.51&nbsp;%) had an empty privacy label. 182 of them (7.68&nbsp;%) claimed not to collect any data.

![Evaluation of the correctness of data types and purposes in privacy labels on iOS. Remember that we can only definitively say when data _is_ collected but if we don't observe data being transmitted, it does not necessarily mean that it is never collected.](../graphs/privacy_labels.pdf){#fig:results-privacy-labels}

[@Fig:results-privacy-labels] shows the comparison of the observed and declared data types and purposes. For most of the data types that we can check, we did not observe apps that incorrectly omitted them from their privacy label or misdeclared them as anonymous. Most notably, we saw 329 apps (13.26&nbsp;%) that transmitted the IDFA, IFDV, or a hashed version thereof without declaring that in their privacy label. Further, 155 apps (6.25&nbsp;%) claimed to collect such a device ID in a way that is not linked to the user, which seems like an obvious contradiction. 98 apps (3.95&nbsp;%) also transmitted the device's location but omitted that in their privacy label and a further 18 apps (0.73&nbsp;%) declared that they only collected the location anonymously even though we observed them linking it to unique identifier for the user or device.

In terms of the purposes, most apps correctly declared whether they used ads and tracking. 118 (4.76&nbsp;%) and 92 apps (3.71&nbsp;%) wrongly claimed not to use ads and tracking respectively despite doing so after all.

## IAB TCF data

163 of the analysed apps have saved `IABTCF` preferences (64 on Android, and 99 on iOS). Of those, 61 were not detected as having a consent dialog by our approach. Manually analysing those showed that 17 do in fact show a dialog that we did not detect but the remaining 44 do not. It could be that those only show a dialog later in the user flow or maybe they include CMP libraries without actually using them.  
Conversely, 282 apps were detected as showing a dialog but have not saved `IABTCF` preferences, confirming our assumption that only relying on TCF data for the analysis would not have been viable (cf. [@sec:cd-situation-mobile-tcf]).
<!-- select platform, count(1) from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app where cast(prefs as text) ~* 'IABTCF' group by platform; -->
<!-- select * from dialogs where cast(prefs as text) ~* 'IABTCF' and not (verdict = 'dialog' or verdict = 'maybe_dialog'); -->
<!-- select * from dialogs where not cast(prefs as text) ~* 'IABTCF' and (verdict = 'dialog' or verdict = 'maybe_dialog'); -->

24 apps only saved `IABTCF` preferences after accepting or rejecting the dialog, but not initially, the remaining 138 saved them even without any interaction with the consent dialog.
<!-- select count(1) from dialogs where prefs->>'initial' ~* 'IABTCF'; -->
<!-- select count(1) from dialogs where not prefs->>'initial' ~* 'IABTCF' and (prefs->>'accepted' ~* 'IABTCF' or prefs->>'rejected' ~* 'IABTCF'); -->

The apps most often set the `IABTCF_gdprApplies` property, with 125 apps setting the property initially and another 27 only setting it after accepting the dialog and one app setting it only after rejecting. In total, 145 apps determine the GDPR to be applicable, 6 apps (incorrectly) determine it not to be and 2 apps set non-spec-compliant values^[The values in question are `-5828135500133229487` and `-6437494263561806870`, with both apps being on iOS coming from the same vendor (`de.prosiebensat1digital.sat1` and `de.prosiebensat1digital.prosieben`). All other `IABTCF` properties these two apps set were either empty or also nonsensical.]. None of the apps changed their determination after accepting or rejecting the dialog.
<!-- select coalesce(prefs->'initial'->'IABTCF_gdprApplies', prefs->'accepted'->'IABTCF_gdprApplies', prefs->'rejected'->'IABTCF_gdprApplies') val, count(1) from dialogs group by val order by count(1) desc; -->
<!-- select * from dialogs where not prefs->'initial' ? 'IABTCF_gdprApplies' and (prefs->'accepted' ? 'IABTCF_gdprApplies' or prefs->'rejected' ? 'IABTCF_gdprApplies'); -->
<!-- select * from dialogs where not prefs->'initial' ? 'IABTCF_gdprApplies' and (prefs->'rejected' ? 'IABTCF_gdprApplies'); -->
<!-- select * from dialogs where prefs ? 'accepted' and prefs->'initial'->'IABTCF_gdprApplies' is distinct from prefs->'accepted'->'IABTCF_gdprApplies'; -->
<!-- select * from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app where prefs->'initial'->>'IABTCF_gdprApplies' not in ('0', '1'); -->
<!-- select * from dialogs where prefs->'initial'->>'IABTCF_gdprApplies' != prefs->'accepted'->>'IABTCF_gdprApplies' or prefs->'initial'->>'IABTCF_gdprApplies' != prefs->'rejected'->>'IABTCF_gdprApplies' or prefs->'accepted'->>'IABTCF_gdprApplies' != prefs->'rejected'->>'IABTCF_gdprApplies'; -->

![Prevalence of CMP providers according to IAB TCF data.](../graphs/tcf_cmps.pdf){#fig:results-tcf-cmps}

`IABTCF_CmpSdkID` specifies which CMP is being used and is set by 111 apps, with six apps specifying an invalid value. [@Fig:results-tcf-cmps] shows the distribution of the different CMP providers. In our dataset, [Sourcepoint](https://www.sourcepoint.com/cmp/) and [Google's Funding Choices](https://blog.google/products/admanager/helping-publishers-manage-consent-funding-choices/) are the most used CMPs by far.

`IABTCF_PublisherCC` specifies the app publisher's country. 62 apps are from Germany according to this, for 22 the CMP didn't know the country, seven are from the US, five from the Netherlands, and three from Spain. The following countries are represented once: France, Hong Kong, Luxembourg, Japan, United Kingdom, and Australia.
<!-- select upper(coalesce(prefs->'initial'->>'IABTCF_PublisherCC', prefs->'accepted'->>'IABTCF_PublisherCC', prefs->'rejected'->>'IABTCF_PublisherCC')) val, count(1) from dialogs group by val order by count(1) desc; -->

Finally, using `IABTCF_TCString`, it is possible to determine the exact consent state the apps are saving. We have collected the accepted state for 60 apps. The TCF allows apps to request consent for ten different purposes like "Store and/or access information on a device" or "Measure ad performance". Most apps store consent for all ten purposes, with an average of 9.10 and a median of 10. Apps can also request consent for vendors, with 860 possible vendors on the [global vendor list](https://vendor-list.consensu.org/v2/archives/vendor-list-v139.json) as of the time of writing. The average for the amount of stored vendor consents is 361.75, the median is 158. All possible vendors were requested by at least seven apps. [@Tbl:results-tcf-vendors] lists the vendors that more than 45 apps stored consent for.
<!-- select count(1) from dialogs where prefs->'accepted'->'IABTCF_TCString' is not null; -->

| Vendor                                            | Count |
|---------------------------------------------------|-------|
| Google Advertising Products                       | 52    |
| The Trade Desk                                    | 50    |
| Smart Adserver                                    | 50    |
| Adform                                            | 50    |
| Flashtalking, Inc.                                | 50    |
| Amazon Advertising                                | 50    |
| RTB House S.A.                                    | 49    |
| Yahoo EMEA Limited                                | 49    |
| Xandr, Inc.                                       | 49    |
| Magnite, Inc.                                     | 49    |
| Sizmek by Amazon                                  | 49    |
| OpenX                                             | 49    |
| PubMatic, Inc.                                    | 49    |
| MediaMath, Inc.                                   | 49    |
| Criteo SA                                         | 49    |
| Meetrics GmbH                                     | 49    |
| SpotX, Inc                                        | 49    |
| advanced store GmbH                               | 49    |
| Publicis Media GmbH                               | 49    |
| TabMo SAS                                         | 49    |
| Exactag GmbH                                      | 49    |
| Otto (GmbH &amp; Co KG)                           | 49    |
| Index Exchange, Inc.                              | 48    |
| Amobee Inc.                                       | 48    |
| Active Agent (ADITION technologies GmbH)          | 48    |
| emetriq GmbH                                      | 48    |
| AudienceProject Aps                               | 48    |
| ADITION technologies GmbH                         | 47    |
| Taboola Europe Limited                            | 47    |
| Yieldlab AG                                       | 47    |
| Platform161 B.V.                                  | 47    |
| Improve Digital                                   | 47    |
| Semasio GmbH                                      | 46    |
| LiveRamp, Inc.                                    | 46    |
| Teads                                             | 46    |
| Mobile Professionals BV                           | 46    |
| Adobe Audience Manager, Adobe Experience Platform | 46    |
| Online Solution                                   | 46    |

:   Counts of vendors apps request consent for according to IAB TCF data. Only vendors requested by more than 45 apps are included. {#tbl:results-tcf-vendors}

The TC string also encodes the language of the consent dialog. Of the 68 apps that initially store a TC string, 63 showed an English consent dialog (our devices were set to English), and five showed a dialog in German.

There is also an older, deprecated TCF specification specifically for mobile apps, the *[Mobile In-App CMP API v1.0](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/b7164119d6b281ac0efb06cb9717e0793fc1f9d0/Mobile%20In-App%20Consent%20APIs%20v1.0%20Final.md)*, which uses `IABConsent` as the prefix for the saved preferences. Only four apps set preferences for this specification without also setting `IABTCF` preferences for the new TCF 2.0 specification. Of those, three only set `IABConsent_SubjectToGDPR` (with one wrongly determining the GDPR not to be applicable), disregarding empty properties. One app additionally set `IABConsent_CMPPresent` to `true` but did not actually show a consent dialog.
<!-- select * from dialogs where cast(prefs as text) ~* 'IABConsent' and not cast(prefs as text) ~* 'IABTCF'; -->

## Validation

For each app, we saved a screenshot immediately after all elements on screen had been analysed to allow us to validate the results afterwards. Apps can prevent screenshots from being taken [@androidopensourceprojectcontributorsWindowManagerLayoutParams2022], in these cases we were not able to take one. This was the case for 42 apps on Android and 50 apps on iOS.

| Detected | Actual | Count |
|----------|--------|-------|
| neither  | link   | 1     |
| neither  | notice | 2     |
| neither  | dialog | 15    |
| link     | notice | 2     |
| link     | dialog | 5     |

:   Counts of wrong classifications from manually validating a random set of 250 apps. {#tbl:results-verdict-validation}

We manually validated the classification for a random set of 250 apps with screenshots. [@Tbl:results-verdict-validation] shows the results of this validation. Notably, we did not encounter a single false positive (meaning detecting something as a consent element that isn't actually one). All classifications were either correct or our analysis missed the consent elements. 25 of the 250 classifications were false negatives.

The discovered false negatives are expected and do not impact the validity of the detected violations. As explained in [@sec:cd-situation-consequences], our approach necessarily misses consent elements due to more detailed information to base an analysis on not being sufficiently available in mobile apps. Not detecting a consent dialog does not cause us to wrongly attribute violations to an app. In these cases, all detected tracking has happened without any user interaction. This means that the apps, regardless of whether a consent dialog is being shown on screen, cannot have obtained valid consent and thus have no legal basis for the tracking. We only perform detection of the other violations in apps where we detected a consent dialog.

We also manually validated all cases where we detected the "accept" button having a significantly different colour than the "reject" button, as our approach cannot determine which of the two is actually highlighted compared to the other. We were able to confirm that it is indeed the "accept" button that is highlighted in all cases.

Finally, we manually validated the remaining violations for 25 randomly selected apps. We found no false positives here, either. There was one app where the "accept" button was larger than the "reject" button but we did not detect the violation.
