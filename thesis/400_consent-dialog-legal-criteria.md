# Criteria for Compliant Consent Dialogs

Before starting to look at actual consent dialogs in the wild, this chapter will develop a list of criteria a consent dialog needs to satisify in order to be compliant. For this purpose, two different legal sources need to be considered: criteria which are set in actual law, and therefore legally binding, and criteria from recommendations of the data protection authorities (DPAs), which are not directly legally binding but rather echo the DPAs' interpretation of the law.

In this thesis, only EU-wide and German sources of law are considered.

## Laws

### Laws to Consider

Any law that restricts the data processing done in apps in any way can in principle introduce criteria on how to obtain consent, and thus has to be considered here. This most obviously includes all laws already discussed in [@sec:legal-background]: the GPDR, the ePrivacy Directive (ePD), and its national implementation in Germany, the TTDSG.

In addition, the GDPR has so-called opening clauses which allow the member states to introduce national laws that diverge from the GDPR in limited aspects. Germany has made use of these opening clauses in the BDSG ("Bundesdatenschutzgesetz"), which thus also needs to be considered.

However, in actuality, most of these laws don't introduce their own conditions on consent:

* Art. 5(3) ePD delegates to Directive 95/46/EC for how consent has to be implemented. This directive was the predecessor to the GDPR, and has been replaced by it. According to Art. 94(2) GDPR, all references to this repealed directive in previous legislation shall be construed as references to the GDPR.
* § 25(1) TTDSG delegates directly to the GDPR for how consent has to be implemented.
* The BDSG only talks about consent in the context of law enforcement (§ 51 BDSG in combination with § 45 BDSG) and is thus not relevant here.

This leaves the GDPR as the only law that defines applicable conditions for consent dialogs.

### Guidelines from the GDPR

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

TODO: Explicit consent for special categories (Art. 9 GDPR), third-country transfer without adequacy decision (Art. 49 GDPR)

### DPA recommendations

Most of the criteria extracted from the GPDR are somewhat vague, making them both hard for companies to implement and difficult to check for automatically, as planned for this thesis. To alleviate this issue, the data protection authorities publish recommendations which detail their interpretation of the law and provide specific guidelines on how to follow them. In most cases, these specific guidelines are better suited for verification in concrete cases and are also commonly used in similar research (TODO: cite).

TODO: BAWÜ!

* Active action is necessary, preticked boxes or mere use of app don't constitute consent (https://www.datenschutzkonferenz-online.de/media/kp/dsk_kpnr_20.pdf; https://edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_202005_consent_en.pdf, 86.).
* Consent has to be voluntary, i.e. it needs to be possible to use app without consenting (https://www.datenschutzkonferenz-online.de/media/kp/dsk_kpnr_20.pdf).
* Notice has to inform about the possibility to withdraw consent at any time without detriment (https://www.datenschutzkonferenz-online.de/media/kp/dsk_kpnr_20.pdf; https://edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_202005_consent_en.pdf, 64.; https://www.baden-wuerttemberg.datenschutz.de/zum-einsatz-von-cookies-und-cookie-bannern-was-gilt-es-bei-einwilligungen-zu-tun-eugh-urteil-planet49/; https://www.ldi.nrw.de/mainmenu_Datenschutz/Inhalt/FAQ/EinwilligungDaten.php; https://lfd.niedersachsen.de/download/161158).
* A consent banner that only mentions cookies can only receive consent under the ePD, not the GDPR (https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 9).
* Necessary information for TTDSG: controller, purpose of access, cookie duration, access for third parties? (https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 12)
* "Okay" is not consent (https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 14; https://lfd.niedersachsen.de/download/161158).
* Even "Agree" is not consent if details are hidden behind another link (https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 14; https://lfd.niedersachsen.de/download/161158).
* Refusing consent has to be possible either through inaction or with the same number of clicks as consenting (https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 14; https://www.lda.bayern.de/media/pm/pm2021_06.pdf; https://lfd.niedersachsen.de/download/161158; https://edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_202005_consent_en.pdf, 114.).
* Concrete purposes need to be listed, "to improve user experience" is not sufficient (https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 16; https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/; https://lfd.niedersachsen.de/download/161158).
* It needs to be possible to only consent to (adequate) subpurposes (https://www.datenschutzkonferenz-online.de/media/oh/20211220_oh_telemedien.pdf, p. 16; https://edpb.europa.eu/sites/default/files/files/file1/edpb_guidelines_202005_consent_en.pdf, 42.).
* The "consent" button cannot be highlighted compared to the "refuse" button (https://www.lda.bayern.de/media/pm/pm2021_06.pdf; https://lfd.niedersachsen.de/startseite/infothek/faqs_zur_ds_gvo/faq-telekommunikations-telemediendatenschutz-gesetz-ttdsg-206449.html#10._Welche_Anforderungen_werden_an_die_Einwilligung_gemaess_25_Abs._1_TTDSG_gestellt_die_grundsaetzlich_beim_Einsatz_von_Cookies_und_bei_der_Einbindung_von_Drittdiensten_einzuholen_ist_; https://lfd.niedersachsen.de/download/161158).
* Consent dialog may not make it impossible to access other required legal notices (https://www.baden-wuerttemberg.datenschutz.de/zum-einsatz-von-cookies-und-cookie-bannern-was-gilt-es-bei-einwilligungen-zu-tun-eugh-urteil-planet49/).
* No purposes may be pre-selected (https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/).
* Third-party recipients have to be mentioned explicitly (https://lfd.niedersachsen.de/download/161158).
* "Accept all" may not toggle additional, previously unselected, purposes (https://lfd.niedersachsen.de/download/161158).

### What can be checked automatically?

* [W] Processing that needs consent (active action) may only be performed after it was given.
* [x] Unambiguous "agree" button (not "okay").
* [x] Refusing consent takes the same number of clicks as giving it or no action at all.
* [x] "Consent" button is not highlighted compared to "refuse" button.
* [x] Using app needs to be possible after refusing/withdrawing consent.
* [ ] TODO: US transfers
* [ ] Consent notice includes at least the identity of the controller, the concrete purposes, storage duration, access for third parties (explicitly listed).
* [ ] Consent notice informs of right to withdrawal.
* [ ] Details may not be hidden after another link if consenting is possible on that screen.
* [ ] Giving consent for subpurposes is possible.
* [ ] No purposes are pre-selected.
* [ ] "Accept all" may not toggle additional, previously unselected, purposes.
