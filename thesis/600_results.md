# Results

* TODO: TCF data
    * There is an older, deprecated TCF specification specifically for mobile apps, the *[Mobile In-App CMP API v1.0](https://github.com/InteractiveAdvertisingBureau/GDPR-Transparency-and-Consent-Framework/blob/b7164119d6b281ac0efb06cb9717e0793fc1f9d0/Mobile%20In-App%20Consent%20APIs%20v1.0%20Final.md)*, which uses `IABConsent` as the prefix for the saved preferences. Only 8 apps set preferences for this specification without also setting `IABTCF` preferences for the new TCF 2.0 specification. Of those, 7 only set `IABConsent_SubjectToGDPR`. One app additionally set `IABConsent_CMPPresent` to `true` but didn't actually show a consent dialog.

    <!-- select * from dialogs where cast(prefs as text) ~* 'IABConsent' and not cast(prefs as text) ~* 'IABTCF'; -->

## Prevalence of Consent Dialogs

## Violations in Consent Dialogs

## Effect of User Choices

* Transmitted data
    * Indicators
    * Adapters
* Tracking companies

## Privacy Labels

## Validation

* For each app, we saved a screenshot immediately after all elements on screen had been analysed. Apps can prevent screenshot from being taken [@androidopensourceprojectcontributorsWindowManagerLayoutParams2022], in these cases we don't take one. Taking screenshot failed for 44 apps on Android and 49 apps on iOS.
* Manually validated a random set of 250 apps with screenshots.

* TODO: The discovered false positives are expected and don't impact the validity of the detected violations. As explained in TODO, our approach is necessarily TODO due to the lack of more detailed information to base an analysis being sufficiently available in mobile apps. Not detecting a consent dialog does not cause us to wrongly attribute violations to an app. In these cases, all detected tracking has happened without any user interaction. This means that the apps, regardless of a consent dialog being shown on screen, cannot have obtained valid consent and thus have no legal basis for the tracking. We only perform detection of the other violations in apps where we detected a consent dialog.
