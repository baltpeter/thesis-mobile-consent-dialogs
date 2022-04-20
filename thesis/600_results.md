# Results

## Prevalence of Consent Dialogs

## Violations in Consent Dialogs

## Effect of User Choices

* Transmitted data
    * Indicators
    * Adapters
* Tracking companies

## Privacy Labels

## IAB TCF data

165 of the analysed apps have saved `IABTCF` preferences. Of those, 60 were not detected as having a consent dialog but our approach. Manually analysing those showed that 15 do in fact show a dialog that we didn't detect but the remaining 45 do not. It could be that those only show a dialog later in the user flow or maybe they include CMP libraries without actually using them.  
Conversely, 291 apps were detected as showing a dialog but have not saved `IABTCF` preferences, confirming our assumption that only relying on TCF data for the analysis would not have been viable (cf. [@sec:cd-situation-mobile-tcf]).
<!-- select * from dialogs where cast(prefs as text) ~* 'IABTCF' and not (verdict = 'dialog' or verdict = 'maybe_dialog'); -->
<!-- select * from dialogs where not cast(prefs as text) ~* 'IABTCF' and (verdict = 'dialog' or verdict = 'maybe_dialog'); -->

24 apps only saved `IABTCF` preferences after accepting or rejecting the dialog but not initially, the remaining 141 saved them even without any interaction with the consent dialog.
<!-- select count(1) from dialogs where prefs->>'initial' ~* 'IABTCF'; -->
<!-- select count(1) from dialogs where not prefs->>'initial' ~* 'IABTCF' and (prefs->>'accepted' ~* 'IABTCF' or prefs->>'rejected' ~* 'IABTCF'); -->

The apps most often set the `IABTCF_gdprApplies` property, with 128 apps setting the property initially and another 27 only setting it after accepting the dialog (no apps set it only after rejecting). In total, 147 apps determine the GDPR to be applicable, 6 apps (incorrectly) determine it not to be and 2 apps set non-spec-compliant values^[The values in question are `-5828135500133229487` and `-6437494263561806870`, with both apps being on iOS coming from the same vendor (`de.prosiebensat1digital.sat1` and `de.prosiebensat1digital.prosieben`). All other `IABTCF` properties these two apps set were either empty or also nonsensical.]. None of the apps changed their determination after accepting or rejecting the dialog.
<!-- select coalesce(prefs->'initial'->'IABTCF_gdprApplies', prefs->'accepted'->'IABTCF_gdprApplies', prefs->'rejected'->'IABTCF_gdprApplies') val, count(1) from dialogs group by val order by count(1) desc; -->
<!-- select * from dialogs where not prefs->'initial' ? 'IABTCF_gdprApplies' and (prefs->'accepted' ? 'IABTCF_gdprApplies' or prefs->'rejected' ? 'IABTCF_gdprApplies'); -->
<!-- select * from dialogs where not prefs->'initial' ? 'IABTCF_gdprApplies' and (prefs->'rejected' ? 'IABTCF_gdprApplies'); -->
<!-- select * from dialogs where prefs ? 'accepted' and prefs->'initial'->'IABTCF_gdprApplies' is distinct from prefs->'accepted'->'IABTCF_gdprApplies'; -->
<!-- select * from dialogs join runs r on r.id = dialogs.run join apps a on a.id = r.app where prefs->'initial'->>'IABTCF_gdprApplies' not in ('0', '1'); -->
<!-- select * from dialogs where prefs->'initial'->>'IABTCF_gdprApplies' != prefs->'accepted'->>'IABTCF_gdprApplies' or prefs->'initial'->>'IABTCF_gdprApplies' != prefs->'rejected'->>'IABTCF_gdprApplies' or prefs->'accepted'->>'IABTCF_gdprApplies' != prefs->'rejected'->>'IABTCF_gdprApplies'; -->

`IABTCF_CmpSdkID` specifies which CMP is being used and is set by 113 apps, with 5 apps specifying an invalid value. [@Fig:results-tcf-cmps] shows the distribution of the different CMP providers. [Sourcepoint](https://www.sourcepoint.com/cmp/) and [Google's Funding Choices](https://blog.google/products/admanager/helping-publishers-manage-consent-funding-choices/) are the most used CMPs by far. TODO: The mapping from the numeric IDs happened using the [CMP list](https://cmplist.consensu.org/v2/cmp-list.json), all invalid CMP IDs were merged into a single group.

![Prevalence of CMP providers according to IAB TCF data.](../graphs/tcf_cmps.pdf){#fig:results-tcf-cmps}

`IABTCF_PublisherCC` specifies the app publisher's country. 61 apps are from Germany according to this, for 22 the CMP didn't know the country, 6 are from the US, 5 from the Netherlands, and 3 from Spain. The following countries are represented once: Luxembourg, United Kingdom, Australia, Hong Kong, Denmark, and Japan.
<!-- select upper(coalesce(prefs->'initial'->>'IABTCF_PublisherCC', prefs->'accepted'->>'IABTCF_PublisherCC', prefs->'rejected'->>'IABTCF_PublisherCC')) val, count(1) from dialogs group by val order by count(1) desc; -->

There is also an older, deprecated TCF specification specifically for mobile apps, the *[Mobile In-App CMP API v1.0](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/b7164119d6b281ac0efb06cb9717e0793fc1f9d0/Mobile%20In-App%20Consent%20APIs%20v1.0%20Final.md)*, which uses `IABConsent` as the prefix for the saved preferences. Only 4 apps set preferences for this specification without also setting `IABTCF` preferences for the new TCF 2.0 specification. Of those, 3 only set `IABConsent_SubjectToGDPR` (with one wrongly determining the GDPR not to be applicable), disregarding empty properties. One app additionally set `IABConsent_CMPPresent` to `true` but didn't actually show a consent dialog.
<!-- select * from dialogs where cast(prefs as text) ~* 'IABConsent' and not cast(prefs as text) ~* 'IABTCF'; -->

## Validation

For each app, we saved a screenshot immediately after all elements on screen had been analysed to allow us to validate the results afterwards. Apps can prevent screenshots from being taken [@androidopensourceprojectcontributorsWindowManagerLayoutParams2022], in these cases we were not able to take one. This was the case for  43 apps on Android and 56 apps on iOS.

We manually validated the classification for a random set of 250 apps with screenshots. [@Tbl:results-verdict-validation] shows the results of this validation. Notably, we didn't encounter a single false positive, all classifications where either correct or our analysis missed the consent elements. 29 of the 250 classifications were false negatives.

| Detected | Actual | Count |
|----------|--------|-------|
| neither  | link   | 5     |
| neither  | notice | 6     |
| neither  | dialog | 9     |
| link     | notice | 3     |
| link     | dialog | 5     |
| notice   | dialog | 1     |

:   Counts of wrong classifications from manually validating a random set of 250 apps. {#tbl:results-verdict-validation}

The discovered false negatives are expected and don't impact the validity of the detected violations. As explained in [@sec:cd-situation-consequences], our approach necessarily misses consent elements due to more detailed information to base an analysis on not being sufficiently available in mobile apps. Not detecting a consent dialog does not cause us to wrongly attribute violations to an app. In these cases, all detected tracking has happened without any user interaction. This means that the apps, regardless of whether a consent dialog is being shown on screen, cannot have obtained valid consent and thus have no legal basis for the tracking. We only perform detection of the other violations in apps where we detected a consent dialog.

We also manually validated all cases where we detected the "accept" having a significantly different colour than the "reject" button, as our approach cannot determine which of the two is actually highlighted compared to the other. We were able to confirm that it is indeed the "accept" button that's highlighted in all cases.
