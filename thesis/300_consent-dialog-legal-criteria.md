# Criteria for Compliant Consent Dialogs {#sec:critera}

Before starting to look at actual consent dialogs in the wild, in this chapter we present a list of criteria a consent dialog needs to meet in order to be legally compliant. For this purpose, we consider two main legal sources: criteria which are set in actual law, and therefore legally binding, and criteria from recommendations of the data protection authorities (DPAs), which are not directly legally binding but rather echo the DPAs' interpretation of the law. Some of the criteria from the DPAs have already been confirmed by court rulings.

In this thesis, we only consider EU-wide and German sources of law, though DPAs from other EU countries have also issued similar guidance and/or decisions (cf. e.g. [ @commissionnationaledelinformatiqueetdeslibertesRefuserCookiesDoit2021; @commissionnationaledelinformatiqueetdeslibertesCookiesAutresTraceurs2020; @roseDatatilsynetDenmark202143101252021; @faCNILFranceSAN20210232022]).

## Conditions on Consent from the Law {#sec:criteria-gdpr}

Any law that restricts the data processing done in apps in any way can in principle introduce criteria on how to obtain consent, and thus has to be considered here. This most obviously includes all laws already discussed in [@Sec:legal-background]: the GDPR, the ePrivacy Directive (ePD), and its national implementation in Germany, the TTDSG.

In addition, the GDPR has so-called opening clauses which allow the member states to introduce national laws that diverge from the GDPR in limited aspects. Germany has made use of these opening clauses in the BDSG ("Bundesdatenschutzgesetz"), which thus also needs to be considered.

However, in actuality, most of these laws do not introduce their own conditions on consent:

* Article 5(3) ePD delegates to Directive 95/46/EC for how consent has to be implemented. This directive was the predecessor to the GDPR, and has been replaced by it. According to Article 94(2) GDPR, all references to this repealed directive in previous legislation shall be construed as references to the GDPR.
* § 25(1) TTDSG delegates directly to the GDPR for how consent has to be implemented.
* The BDSG only talks about consent in the context of law enforcement (§ 51 BDSG in combination with § 45 BDSG) and is thus not relevant here.

This leaves the GDPR as the only law that defines applicable conditions for consent dialogs.

Consent is one of the six possible legal bases for processing personal data from Article 6(1) GDPR. Unsurprisingly, processing that can only rely on consent as a legal basis (like tracking), may thus only happen _after_ consent has been given and the controller needs to be able to demonstrate that consent has been given (Article 7(1) GDPR).

Consent itself is defined in Article 4(11) GDPR, which lists a set of basic conditions an action needs to meet in order to be considered consent, with each of these being further specified by the recitals to the GDPR:

freely given
:   Consent is not *freely given* if there is a clear imbalance between the data subject and the controller, particularly in the case of public authorities (Recital 43 GDPR). The data subject needs to have a genuine and free choice to refuse (or later withdraw) consent without detriment (Recital 42 GDPR). The provision of a contract or service cannot require a data subject's consent if such consent is not necessary for the performance thereof (Article 7(4) GDPR, Recital 43 GDPR).

specific
:   For consent to be *specific*, separate consent should be asked for different processing purposes (Recital 32 GDPR).

informed
:   To be *informed*, a request for consent needs to contain at least the identity of the controller and the purposes of the processing (Recital 42 GDPR).

unambiguous
:   Consent is *unambiguous* if the request for it is “clear, concise and not unnecessarily disruptive to the use of the service for which it is provided” (Recital 32 GDPR).

statement or clear affirmative action
:   Silence, pre-ticked boxes, or inactivity do not constitute consent (Recital 32 GDPR). Instead, it has to be given by a statement “which clearly indicates […] the data subject’s acceptance of the proposed processing”, like ticking a checkbox.

Article 7 GDPR then lists a number of additional conditions for consent:

* If a data subject is asked to give consent through a declaration that also concerns other matters (e.g. also needs to accept a company's terms of service at the same time), the request for consent needs to be “clearly distinguishable from the other matters, in an intelligible and easily accessible form, using clear and plain language” (Article 7(2) GDPR).
* The data subject needs to be able to withdraw consent at any time (Article 7(3) GDPR).
* Before giving consent, the data subject needs to be informed that they have the right to withdraw their consent at any time (Article 7(3) GDPR).
* Later withdrawing consent needs to be as easy as giving it in the first place (Article 7(3) GDPR).

In addition to that, the GDPR places even stricter conditions on consent for special categories of personal data (this includes, among other things, political opinions, biometric and genetic data, as well as data on a person's health and sex life, Article 9 GDPR) and third-country transfers without an adequacy decision (Article 49(1)(a) GDPR), requiring an express statement, separate for this specific purpose [@europeandataprotectionboardGuidelines0520202020].  
Children under the age of 16 years cannot give consent themselves, it instead needs to be given or authorised by their legal guardians (Article 8(1) GDPR).  
We don't consider either in this thesis as we cannot reliably detect them automatically.

## List of Criteria

Most of the conditions extracted directly from the GDPR are somewhat vague, making them both hard for companies to implement and difficult to check for automatically, as planned for this thesis. To alleviate this issue, the data protection authorities publish recommendations which detail their interpretation of the law and provide specific guidelines on how to follow them. In most cases, these specific guidelines are better suited for verification in specific cases and are also used in similar research [@nouwensDarkPatternsGDPR2020; @mattePurposesIABEurope2020; @santosAreCookieBanners2020].

For this thesis, we searched all current publications regarding consent and adjacent topics from all German state data protection authorities, as well as the national DPA, the German data protection conference ("Datenschutzkonferenz", a council of the German DPAs that develops unified recommendations), and the European Data Protection Board (an EU body tasked with ensuring consistent application of data protection law across the EU) for criteria on consent dialogs. The list below consolidates the criteria from the GDPR and DPA recommendations. Where the criteria have already been confirmed by courts, we cite those rulings as well.

It should be emphasised that *any* violation against even a single one of these criteria results in all data processing based on that supposed consent being illegal.

### Criteria for Underlying Circumstances {#sec:criteria-circum}

* Consent needs to be given through a clear, affirmative action like clicking a button or ticking a checkbox (Recital 32 GDPR) [@BundesverbandVerbraucherzentralenUnd1970; @blocherLGRostock7622021; @europeandataprotectionboardGuidelines0520202020, para. 80; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2; @konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 13].
* Processing that needs to rely on consent may only happen after consent has been given (Article 7(1) GDPR) [@FashionIDGmbH1970; @30624211970; @europeandataprotectionboardGuidelines0520202020, para. 90; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.1.1; @konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 12].
* Consent has to be voluntary, i.e. it needs to be possible to use the app without consenting (Recital 42 GDPR) [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderEinwilligungNachDSGVO2019; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2].
* It must be possible to later withdraw consent at any time and this has to be as easy as giving consent in the first place. The data subject needs to be informed of this before giving consent. (Article 7(3) GDPR) [@europeandataprotectionboardGuidelines0520202020, para. 114; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.6; @konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 18]
* A consent dialog may not make it impossible to access other required legal notices (like contact information or privacy policy) [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.1].

### Criteria for Wording and Design of Consent Dialogs {#sec:criteria-design}

* The consent dialog needs to have a clear heading that accurately describes the impact of the processing on the data subject, like "Data disclosure to third parties for tracking purposes." Vague headings like "We respect your privacy." are not sufficient. [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.3.7]
* The "consent" button cannot be highlighted compared to the "refuse" button (e.g. by making it bigger or using a more prominent colour for it) [@bayerischeslandesamtfurdatenschutzaufsichtPressemitteilungLanderubergreifendePrufung2021; @dielandesbeauftragtefurdendatenschutzniedersachsenTelekommunikationsTelemediendatenschutzGesetzTTDSGFragen2021; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.3; @blocherLGRostock7622021].
* The consent notice must be in the language of the country it addresses [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.3.1].
* The consent notice cannot be overly long or complex [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, nos. B.1.3.3.3, B.1.3.3.4].
* A consent notice needs to be clearly distinguishable from other matters like regular terms of service (Article 7(2) GDPR) [@europeandataprotectionboardGuidelines0520202020, para. 81; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.5.1].
* A consent notice that only mentions cookies can only receive consent under the ePD, not the GDPR [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 9; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.3.5.1].

### Criteria on Information to Include in Consent Dialogs

* The consent notice needs to contain at least the following details (Recital 42 GDPR) [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 12; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2; @BundesverbandVerbraucherzentralenUnd1970]:
    * Who is the controller?
    * What is the purpose of the processing?
    * If cookies are used, what is their duration?
    * Is there any access for third parties? 
* Third-party recipients have to be mentioned explicitly [@dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2].
* The consent notice needs to list concrete purposes, vague wordings like "to improve user experience" are not sufficient [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 16; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020].

### Criteria for Buttons and Interactive Elements in Consent Dialogs {#sec:criteria-buttons}

* Refusing consent has to be possible through inaction or with the same number of clicks as consenting [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 14; @bayerischeslandesamtfurdatenschutzaufsichtPressemitteilungLanderubergreifendePrufung2021; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.3].
* A button with the text "Okay" does not sufficiently convey that clicking it is supposed to agree to the consent dialog, and thus does not result in valid consent [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 14; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.1.3.12.1].
* It is not possible to receive consent on a page that doesn't include all necessary details (e.g. if they are hidden behind another link, or on a deeper page in the consent flow) [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 14; @dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020].
* It needs to be possible to only consent to adequate subpurposes and/or recipients (Recital 32 GDPR) [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 16; @europeandataprotectionboardGuidelines0520202020, para. 42; @derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2].
* No purposes may be pre-selected (Recital 32 GDPR) [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. A.4.2; @BundesverbandVerbraucherzentralenUnd1970; @blocherLGRostock7622021].
* Clicking an "Accept all" button may not toggle additional, previously unselected purposes [@dielandesbeauftragtefurdendatenschutzniedersachsenHandreichungDatenschutzkonformeEinwilligungen2020].
* A consent dialog that saves consent but not refusal thereof (and is thus displayed over and over again when refused) is not compliant [@derlandesbeauftragtefurdendatenschutzunddieinformationsfreiheitbaden-wurttembergFAQCookiesUnd2022, no. B.2.2.3].
