# Legal Background {#sec:legal-background}

This chapter will introduce the legal framework that regulates data protection for mobile apps in the EU and Germany. It will explain under which conditions data collection and processing are lawful or unlawful with a focus on data used for tracking purposes, as well as how consent dialogs fit into this.

## Processing of Personal Data {#sec:bg-gdpr}

TODO: Introduce "data subject" and "controller".

* GDPR
    * GDPR (general data protection regulation) went into force in 2018, mandates a data protection framework that is consistent across the whole EU and also more strict than previous regulation in this area. 
    * Territorial scope
    * Deals with "Processing" of "personal data" (Art. 2(1) GDPR)
        * defined in Art. 4 GDPR
        * explicitly broad terms
        * in essence any data that can somehow be connected to a natural person and that a company deals with in some way is covered by the GDPR
        * includes pseudonymous data (i.e. TODO)
    * Legal basis for processing
        * conclusive list of them defined in Art. 6(1)(a–f) GDPR, any processing of PD can only be legal if it fulfills one of these conditions:
            * list them
        * In the context of tracking, c), d), e) obviously not applicable [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, p. 27]
        * Law itself doesn't directly answer the question which of the remaining three can be used. For that, one can look to the data protection authorities. Those are public authorities in each member state tasked with enforcing the GDPR in their respective jurisdiction. They publish their interpretation of unclear aspects of the law like this in recommendations. While those recommendations aren't legally binding in and of themselves, the DPAs can issue sanctations (including fines) to companies who don't follow them.
        * EDPB is TODO
        * EDPB says that b) and f) can typically not be used for tracking.
            * https://edpb.europa.eu/our-work-tools/our-documents/guidelines/guidelines-22019-processing-personal-data-under-article-61b_en
            * So does BAWÜ (https://www.baden-wuerttemberg.datenschutz.de/faq-zu-cookies-und-tracking-2/, B.3.1.1.5, B.3.2.10.3); DSK [@konferenzderunabhangigendatenschutzaufsichtsbehordendesbundesundderlanderOrientierungshilfeAufsichtsbehordenFur2021, sec. IV]; and others (TODO)
        * That leaves only consent as a potential legal basis for tracking. The GDPR has high conditions for what is considered valid consent. Chapter TODO will deal with this in detail.

## Storing and Accessing Information on Terminal Equipment

* ePD/TTDSG
    * Came before GDPR, introduced in 2009?
    * Unlike GDPR, doesn't deal with data protection but integrity of a person's terminal equipment
    * As a directive not directly legally binding, needs to be implemented into national law by member states
    * In this context, only Art. 5(3) ePD relevant
    * Not just personal data but TODO
    * For a long time, Germany didn't properly implement the ePD, TODO, Planet49
    * In Dec 2021: TTDSG. § 25 TTDSG now implements Art. 5(3) ePD.
    * ePD and TTDSG don't know legitimate interest or contractual necessity => even stricter conditions for not needing consent

## Transferring Personal Data to Third Countries

* Schrems II
    * generally, transferring data to country outside the EU is forbidden unless it there is an exception that allows it (Art. 44–50 GDPR)
    * Most simply, transfers to third countries (i.e. countries not in the EU) can be based on a so-called adequacy decision, one of the those exceptions (Art. TODO GDPR). The EC? has issued suchs AD for a number of third countries (including TODO). Based on an AD, data transfers to the respective third country can happen without any special additional safeguards.
    * Previously, there was also such an AD for the US (where most tracking providers, and many other internet infrastructure companies, are based), the so-called Privacy Shield
    * Invalidated by the ECJ in July 2020 Schrems II ruling due to TODO
    * As such, legal data transfers to the US now much harder or even impossible in many cases [https://diercks-digital-recht.de/2021/01/die-rechtslage-im-transatlantischen-datenverkehr-teil-1-von-4-wie-ordnet-die-us-regierung-das-schrems-ii-urteil-des-eugh-ein/ https://diercks-digital-recht.de/2021/02/rechtslage-im-transatlantischen-datenverkehr-teil-2-von-5-loesungen-der-aufsichtsbehoerden-aus-dem-elfenbeinturm/ https://noyb.eu/en/next-steps-users-faqs]

    * TODO: https://www.baden-wuerttemberg.datenschutz.de/wp-content/uploads/2021/10/OH-int-Datentransfer.pdf

---

TODO:
    * Consent dialogs (maybe merge into something else)
    * Consent notices (don't have much of an effect, other than maybe Art. 13/14 GDPR)
