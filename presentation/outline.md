* Consent dialogs
    * Pretty much universally agreed that they are super annyoing
    * But it's much worse than that: previous research has shown that they are actively harmful
        * quote some
* often said to be the GDPR's fault. Actually true? For that, let's take a quick look at what the GDPR is actually about.
    * GDPR processing of personal data (includes pseudo!)
        * needs legal basis (common misconception: only consent BUT true for tracking)
            * cross out in steps
    * Art. 5(3) ePD: quote
        * also applies to non-personal data when accessed from terminal equipment
        * exceptions very narrow, only refer to strict technical necessity
    * Schrems II
    * summary slide?
* criteria (not full list)
    * Clear affirmative action (no tracking before consent)
    * Unambiguous labels necessary (no "okay")
    * Refusing needs to be as easy as accepting (if there is a first-layer "accept", "reject" also needs to be present)
    * "Accept" not highlighted compared to "reject" (by size or color)
    * consent cannot be mandatory (app can't stop after refusing consent)
* on the web, we know that a worrying amount of dialogs violates these criteria
    * quote noyb etc.
* on mobile, also many CDs but no research yet
* from our prior work, already basic instrumentation tooling for Android and iOS, extended for this thesis
    * emu on Android, jailbroken iPhone on iOS
    * can collect traffic using mitmproxy + objection/SSL Kill Switch 2
    * can manage emulator/device: manage apps, set permissions, reset, start
    * for analysing elements and interaction: Appium 
* so, how can we automatically analyse apps?
    * TCF standard (illegal btw) on the web, allows communication with CD
    * also available on mobile, but we found that rarely used
    * what about CMPs? also rarely used
    * => unfortunately, we have to use text-based matching
    * distinguish link, notice, dialog (screenshots)
    * use regexes to look for common elements of each
    * additionally use keyword score to weed out TOS-only notices
* now we only need apps
    * Android: scrape top charts; use PlaystoreDownloader
    * iOS: discovered old internal iTunes API; previously used 3uTools (manual-ish), after lot of arguing with Apple servers found way to programmatically download apps, extended IPATool with that (video)
    * from top 100 per category, we successfully downloaded 3,313 on Android, 2,481 on iOS
* Results for types and violations
    * successfully analysed 4,388 apps with 2,068 apps on Android and 2,320 apps on iOS, corresponding to 62.42 % and 93.51 % of the downloaded apps, respectively.
    * types table (merge maybes)
        * in total, 785 apps (17.89 %) had one of the consent elements we detect

    * UpSet plot (drop tiny sets)
        * later show top chart position
    * In total, we have detected at least one dark pattern in 347 of the 384 apps with a dialog (90.36 %). The share of dark patterns in dialogs is slightly higher on Android with 136 of 149 dialogs (91.28 %) compared to 211 of 235 (89.79 %) on iOS.
    * Not violations on their own! Only results in obtained consent being invalid. Actual violation if tracking based on that supposed consent.
    * We found that 328 of the 384 apps with a dialog (85.42 %) transmitted pseudonymous data in any of our runs. Further, 297 of the 347 apps with a detected dark pattern in their dialog (85.59 %) transmitted pseudonymous data in any of our runs. Taking that into consideration, we have identified that 77.34 % of the 384 detected dialogs failed to acquire valid consent for the tracking that they perform.
* effect of user choices
    * interact with discovered buttons
    * to analyse transmitted data: as request data is often obfuscated and ridiculously nested, we use 26 adapters for common tracking endpoints (already cover more than 10% of all traffic!)
        * for everything else: indicator matching of honey data
* user choice results
    * Even before interaction, 33.32 % of requests were identified as going to trackers according to Exodus, with 78.08 % of apps making at least one request to a tracker.
    * fig of most common trackers
    * 72.95 % of apps transmitted unique device ID without interaction
    * fig of data types (explain pseudo and ano definition)
    * fig of types vs. trackers

    * collected traffic for 330 apps (9,342 requests) after accepting, 28 apps (323 requests) after rejecting (due to the low number of dialogs which even _have_ a "reject" button we could click). Thus results for rejected runs not representative.
    * table of: "In the traffic before interaction, 33.32 % […]. Furthermore, in the initial […]" (p. 47)
    * fig of accepted data types (compare to initial)
* privacy labels
    * quick explanation (screenshot of label)
    * 112 of the 2,481 apps on iOS (4.51 %) had an empty privacy label. 182 of them (7.68 %) claimed not to collect any data.
    * we can only check a subset of declared types and purposes, also ambiguity in definitions
    * fig of privacy labels
* TODO: very quick rundown of IAB TCF data
* TODO: validation
* TODO: Short conclusion and future work

---

TODO:

* Requests/hosts figure?
* Cookies figure?
* Limitations?
