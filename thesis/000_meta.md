---
# actual parameters
title: Informed Consent? A Study of “Consent Dialogs” on Android and iOS
type: Master’s Thesis
author_name: Benjamin Altpeter
author_matr_num: <redacted>
supervisor: Prof. Dr. Martin Johns
date: May 04, 2022
abstract: |
  Consent dialogs have become ubiquitous with seemingly every website and app pleading users to agree to their personal data being processed and their behaviour being tracked, often with the help of tens or even hundreds of third-party companies. They are an effort by website and app publishers to comply with data protection legislation like the GDPR, which imposes strict limits on how companies can process data. Previous research has established that companies often apply dark patterns to illegally nudge users into agreeing and that at the same time tracking is more common than ever with both websites and apps regularly automatically transmitting telemetry data.

  But so far, there has been almost no research into consent dialogs on mobile. In this thesis, we study consent dialogs on Android and iOS in an automated and dynamic manner, analysing 4,388 popular apps from both platforms. We identify different types of consent elements in the apps and analyse their prevalence. We also identify dark patterns and violations by the apps based on a list of criteria for a legally compliant consent dialog that we have compiled. Finally, we measure the effect of the user's choice in the consent dialog by comparing the traffic from before any interaction with the traffic after accepting and rejecting the dialog and analysing contacted trackers and transmitted data types.  
  The results show that more than 90&nbsp;% of consent dialogs implement at least one dark pattern and that a majority of apps transmits tracking data regardless of consent status.

# pandoc options
bibliography: ../thesis/bibliography.json
link-citations: true
reference-section-title: Bibliography

# pandoc-crossref options (see: https://lierdakil.github.io/pandoc-crossref/#customization)
cref: true
chapters: true
codeBlockCaptions: true
figPrefix:
  - "Figure"
  - "Figures"
eqnPrefix:
  - "Equation"
  - "Equations"
tblPrefix:
  - "Table"
  - "Tables"
lstPrefix:
  - "Listing"
  - "Listings"
secPrefix:
  - "Section"
  - "Sections"
---
