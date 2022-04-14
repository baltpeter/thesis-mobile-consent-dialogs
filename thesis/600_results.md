# Results

TODO: TCF data
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
