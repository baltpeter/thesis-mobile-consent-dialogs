# Outline

* Introduction
* Legal background
    * GDPR
        * "Processing" of "personal data"
        * Territorial scope
        * Legal basis for processing
        * Consent for tracking
    * ePD/TTDSG
    * Schrems II
* Related work
* Criteria for compliant consent dialogs
* Consent dialogs in the wild
    * Situation on the web
        * CMPs
        * IAB TCF
    * Situation on mobile
        * IAB TCF exists but barely used
        * CMPs also rarely used
    * Consequences for analysis
* Device instrumentation framework
    * Platforms
        * Emulator for Android
        * Real device for iOS
        * Device preparation
    * Device instrumentation
        * XCUITest (iOS) and UiAutomator2 (Android)
        * Appium as common interface over the two
            * Setup problems on iOS
        * Custom platform-specific interfaces
    * Traffic collection
        * mitmproxy
        * Certification pinning bypasses
        * Background noise filtering
    * Dataset
        * App selection
        * App acquisition
* Analysis method
    * Consent dialog detection
        * Existing research on the web
        * Our approach
        * Classification (dialog, notice, link)
        * Interaction with CD
    * Violation identification
    * Tracking content classification
        * Endpoint-specific adapters
        * Previous approach (extended?)
    * Privacy labels
* Results
    * Consent dialog types and frameworks
    * Violations
    * Effect of user choices
        * Transmitted data
            * Indicators
            * Adapters
        * Tracking companies
    * Privacy labels
    * Validation
* Discussion
    * Comparism with results for the web
    * Limitations
        * No interaction with apps beyond consent dialog (e.g. first-run wizards not considered)
        * Only considers text that is machine-readable and available to Appium
        * Only DE and EN supported
        * Appium can only access a very limited amount of element attributes
        * Analysis provides lower bound
* Conclusion
    * Future work
