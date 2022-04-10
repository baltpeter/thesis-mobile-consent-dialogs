# Criteria for Compliant Consent Dialogs {#sec:critera}

Before starting to look at actual consent dialogs in the wild, this chapter will develop a list of criteria a consent dialog needs to satisify in order to be compliant. For this purpose, two different legal sources need to be considered: criteria which are set in actual law, and therefore legally binding, and criteria from recommendations of the data protection authorities (DPAs), which are not directly legally binding but rather echo the DPAs' interpretation of the law.

In this thesis, only EU-wide and German sources of law are considered, though DPAs from other EU countries have also issued similar guidance and/or decisions (cf. e.g. [ @commissionnationaledelinformatiqueetdeslibertesRefuserCookiesDoit2021; @commissionnationaledelinformatiqueetdeslibertesCookiesAutresTraceurs2020; @roseDatatilsynetDenmark202143101252021; @faCNILFranceSAN20210232022]).

## Laws

Any law that restricts the data processing done in apps in any way can in principle introduce criteria on how to obtain consent, and thus has to be considered here. This most obviously includes all laws already discussed in [@sec:legal-background]: the GPDR, the ePrivacy Directive (ePD), and its national implementation in Germany, the TTDSG.

In addition, the GDPR has so-called opening clauses which allow the member states to introduce national laws that diverge from the GDPR in limited aspects. Germany has made use of these opening clauses in the BDSG ("Bundesdatenschutzgesetz"), which thus also needs to be considered.

However, in actuality, most of these laws don't introduce their own conditions on consent:

* Art. 5(3) ePD delegates to Directive 95/46/EC for how consent has to be implemented. This directive was the predecessor to the GDPR, and has been replaced by it. According to Art. 94(2) GDPR, all references to this repealed directive in previous legislation shall be construed as references to the GDPR.
* § 25(1) TTDSG delegates directly to the GDPR for how consent has to be implemented.
* The BDSG only talks about consent in the context of law enforcement (§ 51 BDSG in combination with § 45 BDSG) and is thus not relevant here.

This leaves the GDPR as the only law that defines applicable conditions for consent dialogs.

### Criteria from the GDPR {#sec:criteria-gdpr}

Consent is one of the six possible legal bases for processing personal data from Art. 6(1) GDPR. Unsurprisingly, processing that can only rely on consent as a legal basis (like tracking for example, see [@sec:bg-gdpr]), may thus only happen _after_ consent has been given and the controller needs to be able to demonstrate that consent has been given (Art. 7(1) GDPR).

Consent itself is defined in Art. 4(11) GDPR, which lists a set of basic properties an action needs to meet in order to be considered consent, with each of these being further specified by the recitals to the GDPR:

freely given
:   According to Recital 43 GDPR, consent is not *freely given* if there is a clear imbalance between the data subject and the controller, particularly in the case of public authorities (which isn't really relevant here). According to Recital 42 GDPR, the data subject needs to have a genuine and free choice to refuse (or later withdraw) consent without detriment. The provision of a contract or service cannot require a data subject's consent if such consent is not necessary for the performance thereof (Art. 7(4) GDPR, Recital 43 GDPR).

specific
:   According to Recital 32 GDPR, for consent to be *specific*, separate consent should be asked for different processing purposes.

informed
:   According to Recital 42 GDPR, a request for consent needs to contain at least the identity of the controller and the purposes of the processing to be *informed*.

unambiguous
:   According to Recital 32 GDPR, consent is *unambiguous* if the request for it is “clear, concise and not unnecessarily disruptive to the use of the service for which it is provided”.

statement or clear affirmative action
:   According to Recital 32 GDPR, silence, pre-ticked boxes, or inactivity do not constitute consent. Instead, it has to be given by a statement which “which clearly indicates […] the data subject’s acceptance of the proposed processing”, like ticking a checkbox.

Art. 7 GDPR then lists a number of additional conditions for consent:

* If a data subject is asked to give consent through a declaration that also concerns other matters (e.g. also needs to accept a company's terms of service at the same time), the request for consent needs to be “clearly distinguishable from the other matters, in an intelligible and easily accessible form, using clear and plain language” (Art. 7(2) GDPR).
* The data subject needs to be able to withdraw consent at any time (Art. 7(3) GDPR).
* Before giving consent, the data subject needs to be informed that they have the right to withdraw their consent at any time (Art. 7(3) GDPR).
* Later withdrawing consent needs to be as easy as giving it in the first place (Art. 7(3) GDPR).

In addition to that, the GDPR places even stricter conditions on consent for special categories of personal data (this includes, among other things, political opinions, biometric and genetic data, as well as data on a person's health and sex life, Art. 9 GDPR) and third-country transfers without an adequacy decision (Art. 49(1)(a) GDPR), requiring an express statement, separate for this specific purpose [@europeandataprotectionboardGuidelines0520202020].  
Children under the age of 16 years cannot give consent themselves, it needs to be given or authorised by their legal guardians (Art. 8(1) GDPR).  
We don't consider these cases in this thesis as we can't reliably detect them automatically.

## DPA recommendations

Most of the criteria extracted directly from the GPDR are somewhat vague, making them both hard for companies to implement and difficult to check for automatically, as planned for this thesis. To alleviate this issue, the data protection authorities publish recommendations which detail their interpretation of the law and provide specific guidelines on how to follow them. In most cases, these specific guidelines are better suited for verification in concrete cases and are also commonly used in similar research (TODO: cite).

### Criteria from DPA recommendations

For this thesis, all current publications regarding consent and adjacent topics from all German data protection authorities (which includes all state DPAs, as well as the national DPA), the German data protection conference ("Datenschutzkonferenz", a council of the German DPAs that develops unified recommendations), and the European Data Protection Board (an EU body tasked with ensuring consistent application of data protection law across the EU), were searched for criteria on consent dialogs, resulting in the list presented below. Criteria that already directly follow from the text of the law are not included here again.

#### Criteria for underlying circumstances {#sec:criteria-circum}

* Consent has to be voluntary, i.e. it needs to be possible to use the app without consenting [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderEinwilligungNachDSGVO2019; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2].
* A consent dialog may not make it impossible to access other required legal notices (like contact information or privacy policy) [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.1].

#### Criteria for wording and design of consent dialogs {#sec:criteria-design}

* The consent dialog needs to have a clear heading that accurately describes the impact of the processing on the data subject, like "Data disclosure to third parties for tracking purposes". Vague headings like "We respect your privacy." are not sufficient. [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.3.7]
* The "consent" button cannot be highlighted compared to the "refuse" button (e.g. by making it bigger or using a more prominent colour for it) [@bayerischeslandesamtfurdatenschutzaufsichtPressemitteilungLanderubergreifendePrufung2021; @dielandesbeauftragtefurdendatenschutzniedersachsenTelekommunikationsTelemediendatenschutzGesetzTTDSGFragen2021; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.3].
* The consent notice must be in the language of the country it addresses [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.3.1].
* The consent notice cannot be overly long or complex [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, nos. B.1.3.3.3, B.1.3.3.4].
* A consent banner that only mentions cookies can only receive consent under the ePD, not the GDPR [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 9; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.3.5.1].

#### Criteria on information to include in consent dialogs

* The consent notice needs to contain at least the following details [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 12; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2]:
    * Who is the controller?
    * What is the purpose of the processing?
    * If cookies are used, what is their duration?
    * Is there any access for third parties? 
* Third-party recipients have to be mentioned explicitly [@dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2].
* The consent notice needs to list concrete purposes, vague wordings like "to improve user experience" are not sufficient [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 16; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020].

#### Criteria for buttons and interactive elements in consent dialogs {#sec:criteria-buttons}

* Refusing consent has to be possible through inaction or with the same number of clicks as consenting [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 14; @bayerischeslandesamtfurdatenschutzaufsichtPressemitteilungLanderubergreifendePrufung2021; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @europeandataprotectionboardGuidelines0520202020, para. 114; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.3].
* A button with the text "Okay" does not sufficiently convey that clicking it is supposed to agree to the consent dialog, and thus doesn't result in valid consent [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 14; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.3.12.1].
* It is not possible to receive consent on a page that doesn't include all necessary details (e.g. if they are hidden behind another link, or on a deeper page in the consent flow) [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 14; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020].
* It needs to be possible to only consent to adequate subpurposes and/or recipients [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 16; @europeandataprotectionboardGuidelines0520202020, para. 42; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2].
* No purposes may be pre-selected [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2].
* Clicking an "Accept all" button may not toggle additional, previously unselected purposes [@dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020].
* A consent dialog that saves consent but not refusal thereof (and is thus displayed over and over again when refused) is not compliant [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.2.2.3].

## Criteria to be checked automatically

TODO: NLP beyond the scope of this thesis

* [W] Processing that needs consent (active action) may only be performed after it was given.
* [x] Unambiguous "agree" button (not "okay").
* [x] Refusing consent takes the same number of clicks as giving it or no action at all.
* [x] "Consent" button is not highlighted compared to "refuse" button.
* [x] Using app needs to be possible after refusing/withdrawing consent.
* [ ] TODO: US transfers
* [ ] TODO: Language
* [ ] TODO: Heading (see list from BaWü)
* [ ] Consent notice includes at least the identity of the controller, the concrete purposes, storage duration, access for third parties (explicitly listed).
* [ ] Consent notice informs of right to withdrawal.
* [ ] Details may not be hidden after another link if consenting is possible on that screen.
* [ ] Giving consent for subpurposes is possible.
* [ ] No purposes are pre-selected.
* [ ] "Accept all" may not toggle additional, previously unselected, purposes.
