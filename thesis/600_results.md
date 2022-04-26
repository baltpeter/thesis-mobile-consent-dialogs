# Results

<!-- TODO:

* How many apps succeeded?
* Why did the failing ones fail?
* Time analysis took to run. -->

## Network Traffic and Tracking

![Number of requests and unique hosts contacted per app without any user interaction. Three apps which did more than 1000 requests are omitted in this graph. Those are: `com.prequel.app` on Android with 2500 requests, and `com.audiomack.iphone` and `com.storycover` on iOS with 2383 and 1019 requests, respectively.](../graphs/requests_hosts_per_app.pdf){#fig:results-requests-hosts-per-app}

![Number of apps that sent requests to the 25 most common trackers in our dataset according to Exodus [@exoduscontributorsExodusTrackerInvestigation2022]. The trackers are coloured by the country they are based in.](../graphs/exodus_tracker_counts.pdf){#fig:results-exodus-tracker-counts}

* Percentage of traffic that Exodus classifies as tracking
* Transmitted data
    * Indicators
    * Adapters

<!-- select c.platform, avg(c.count) from (select count(1) count, platform from filtered_requests where run_type='initial' group by name, version, platform) as c group by c.platform; -->

<!-- select count(1) from apps where platform='ios' and not exists(select 1 from filtered_requests fr where fr.name=apps.name and fr.version=apps.version and fr.platform=apps.platform); -->
<!-- select count(1) from apps where platform='android' and not exists(select 1 from filtered_requests fr where fr.name=apps.name and fr.version=apps.version and fr.platform=apps.platform); -->

## Prevalence of Consent Dialogs

## Violations in Consent Dialogs

## Effect of User Choices

To gain insights into how different choices in the consent dialogs affect the tracking going on, we collected the app's network traffic, distinguishing between the initial run without any user input, and the runs after accepting and rejecting the dialog if present. We collected traffic for 330 apps after accepting and 28 apps after rejecting. The latter number might seem low but can be explained by the fact that most dialogs we found either didn't contain a first-layer "reject" button at all or only had one with an ambiguous label and we only clicked ones with a clear label.
<!-- select count(1) from runs where run_type='accepted'; -->
<!-- select count(1) from runs where run_type='rejected'; -->

Given the low number of apps for which we have traffic after rejecting, which would not be representative, we don't analyse the change in tracking after rejected. The likelihood of a re-identified device skewing the results is significantly lower for the accepted runs as those came immediately after the initial run without interaction, which should not have affected a potential server-side consent status.

<!-- select count(1) from filtered_requests where run_type = 'initial'; -->
<!-- select count(1) from filtered_requests where run_type = 'accepted'; -->
<!-- select count(1) from filtered_requests where run_type = 'rejected'; -->

<!-- For initial runs: 3201 of 4388 apps (72.95 %) transmit pseudonymous data.
For accepted runs: 181 of 330 apps (54.85 %) transmit pseudonymous data.
    -> Of those, 46 apps didn't transmit pseudonymous data initially.
For rejected runs: 13 of 28 apps (46.43 %) transmit pseudonymous data.
    -> Of those, 1 apps didn't transmit pseudonymous data initially. -->

## Privacy Labels

## IAB TCF data

163 of the analysed apps have saved `IABTCF` preferences (64 on Android, and 99 on iOS). Of those, 61 were not detected as having a consent dialog by our approach. Manually analysing those showed that 17 do in fact show a dialog that we didn't detect but the remaining 44 do not. It could be that those only show a dialog later in the user flow or maybe they include CMP libraries without actually using them.  
Conversely, 282 apps were detected as showing a dialog but have not saved `IABTCF` preferences, confirming our assumption that only relying on TCF data for the analysis would not have been viable (cf. [@sec:cd-situation-mobile-tcf]).
<!-- select platform, count(1) from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app where cast(prefs as text) ~* 'IABTCF' group by platform; -->
<!-- select * from dialogs where cast(prefs as text) ~* 'IABTCF' and not (verdict = 'dialog' or verdict = 'maybe_dialog'); -->
<!-- select * from dialogs where not cast(prefs as text) ~* 'IABTCF' and (verdict = 'dialog' or verdict = 'maybe_dialog'); -->

24 apps only saved `IABTCF` preferences after accepting or rejecting the dialog but not initially, the remaining 138 saved them even without any interaction with the consent dialog.
<!-- select count(1) from dialogs where prefs->>'initial' ~* 'IABTCF'; -->
<!-- select count(1) from dialogs where not prefs->>'initial' ~* 'IABTCF' and (prefs->>'accepted' ~* 'IABTCF' or prefs->>'rejected' ~* 'IABTCF'); -->

The apps most often set the `IABTCF_gdprApplies` property, with 125 apps setting the property initially and another 27 only setting it after accepting the dialog and one app setting it only after rejecting. In total, 145 apps determine the GDPR to be applicable, 6 apps (incorrectly) determine it not to be and 2 apps set non-spec-compliant values^[The values in question are `-5828135500133229487` and `-6437494263561806870`, with both apps being on iOS coming from the same vendor (`de.prosiebensat1digital.sat1` and `de.prosiebensat1digital.prosieben`). All other `IABTCF` properties these two apps set were either empty or also nonsensical.]. None of the apps changed their determination after accepting or rejecting the dialog.
<!-- select coalesce(prefs->'initial'->'IABTCF_gdprApplies', prefs->'accepted'->'IABTCF_gdprApplies', prefs->'rejected'->'IABTCF_gdprApplies') val, count(1) from dialogs group by val order by count(1) desc; -->
<!-- select * from dialogs where not prefs->'initial' ? 'IABTCF_gdprApplies' and (prefs->'accepted' ? 'IABTCF_gdprApplies' or prefs->'rejected' ? 'IABTCF_gdprApplies'); -->
<!-- select * from dialogs where not prefs->'initial' ? 'IABTCF_gdprApplies' and (prefs->'rejected' ? 'IABTCF_gdprApplies'); -->
<!-- select * from dialogs where prefs ? 'accepted' and prefs->'initial'->'IABTCF_gdprApplies' is distinct from prefs->'accepted'->'IABTCF_gdprApplies'; -->
<!-- select * from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app where prefs->'initial'->>'IABTCF_gdprApplies' not in ('0', '1'); -->
<!-- select * from dialogs where prefs->'initial'->>'IABTCF_gdprApplies' != prefs->'accepted'->>'IABTCF_gdprApplies' or prefs->'initial'->>'IABTCF_gdprApplies' != prefs->'rejected'->>'IABTCF_gdprApplies' or prefs->'accepted'->>'IABTCF_gdprApplies' != prefs->'rejected'->>'IABTCF_gdprApplies'; -->

`IABTCF_CmpSdkID` specifies which CMP is being used and is set by 111 apps, with 6 apps specifying an invalid value. [@Fig:results-tcf-cmps] shows the distribution of the different CMP providers. In our dataset, [Sourcepoint](https://www.sourcepoint.com/cmp/) and [Google's Funding Choices](https://blog.google/products/admanager/helping-publishers-manage-consent-funding-choices/) are the most used CMPs by far. TODO: The mapping from the numeric IDs happened using the [CMP list](https://cmplist.consensu.org/v2/cmp-list.json), all invalid CMP IDs were merged into a single group.

![Prevalence of CMP providers according to IAB TCF data.](../graphs/tcf_cmps.pdf){#fig:results-tcf-cmps}

`IABTCF_PublisherCC` specifies the app publisher's country. 62 apps are from Germany according to this, for 22 the CMP didn't know the country, 7 are from the US, 5 from the Netherlands, and 3 from Spain. The following countries are represented once: France, Hong Kong, Luxembourg, Japan, United Kingdom, and Australia.
<!-- select upper(coalesce(prefs->'initial'->>'IABTCF_PublisherCC', prefs->'accepted'->>'IABTCF_PublisherCC', prefs->'rejected'->>'IABTCF_PublisherCC')) val, count(1) from dialogs group by val order by count(1) desc; -->

Finally, using `IABTCF_TCString`, it is possible to determine the exact consent state the apps are saving. We have collected the accepted state for 60 apps. The TCF allows apps to request consent for ten different purposes like "Store and/or access information on a device" or "Measure ad performance". Most apps store consent for all ten purposes, with an average of 9.10 and a median of 10. Apps can also request consent for vendors, with 860 possible vendors on the [global vendor list](https://vendor-list.consensu.org/v2/archives/vendor-list-v139.json) as of the time of writing. The average for the amount of stored vendor consents is 361.75, the median is 158. All possible vendors were requested by at least 7 apps. [@Tbl:results-tcf-vendors] lists the vendors that more than 45 apps stored consent for.
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

The TC string also encodes the language of the consent dialog. Of the 68 apps that initially store a TC string, 63 showed an English consent dialog (our devices were set to English), and 5 showed a dialog in German. Due to the small sample size of apps implementing the TCF we don't go into the remaining information TC strings hold (cf. [@sec:cd-tcf-web]).

There is also an older, deprecated TCF specification specifically for mobile apps, the *[Mobile In-App CMP API v1.0](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/b7164119d6b281ac0efb06cb9717e0793fc1f9d0/Mobile%20In-App%20Consent%20APIs%20v1.0%20Final.md)*, which uses `IABConsent` as the prefix for the saved preferences. Only 4 apps set preferences for this specification without also setting `IABTCF` preferences for the new TCF 2.0 specification. Of those, 3 only set `IABConsent_SubjectToGDPR` (with one wrongly determining the GDPR not to be applicable), disregarding empty properties. One app additionally set `IABConsent_CMPPresent` to `true` but didn't actually show a consent dialog.
<!-- select * from dialogs where cast(prefs as text) ~* 'IABConsent' and not cast(prefs as text) ~* 'IABTCF'; -->

## Validation

For each app, we saved a screenshot immediately after all elements on screen had been analysed to allow us to validate the results afterwards. Apps can prevent screenshots from being taken [@androidopensourceprojectcontributorsWindowManagerLayoutParams2022], in these cases we were not able to take one. This was the case for  42 apps on Android and 50 apps on iOS.

We manually validated the classification for a random set of 250 apps with screenshots. [@Tbl:results-verdict-validation] shows the results of this validation. Notably, we didn't encounter a single false positive, all classifications where either correct or our analysis missed the consent elements. 25 of the 250 classifications were false negatives.

| Detected | Actual | Count |
|----------|--------|-------|
| neither  | link   | 1     |
| neither  | notice | 2     |
| neither  | dialog | 15    |
| link     | notice | 2     |
| link     | dialog | 5     |

:   Counts of wrong classifications from manually validating a random set of 250 apps. {#tbl:results-verdict-validation}

The discovered false negatives are expected and don't impact the validity of the detected violations. As explained in [@sec:cd-situation-consequences], our approach necessarily misses consent elements due to more detailed information to base an analysis on not being sufficiently available in mobile apps. Not detecting a consent dialog does not cause us to wrongly attribute violations to an app. In these cases, all detected tracking has happened without any user interaction. This means that the apps, regardless of whether a consent dialog is being shown on screen, cannot have obtained valid consent and thus have no legal basis for the tracking. We only perform detection of the other violations in apps where we detected a consent dialog.

We also manually validated all cases where we detected the "accept" having a significantly different colour than the "reject" button, as our approach cannot determine which of the two is actually highlighted compared to the other. We were able to confirm that it is indeed the "accept" button that's highlighted in all cases.

Finally, we manually validated the remaining violations for 25 randomly selected apps. We found no false positives here, either. There was one app where the "accept" button was larger than the "reject" button but we didn't detect the violation.

TODO: Compare with initial manual analysis.
