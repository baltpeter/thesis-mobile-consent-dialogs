const normalizeFragments = (frags, enforce_word_boundaries = false) =>
    frags
        .map((frag) =>
            typeof frag === 'string'
                ? new RegExp(enforce_word_boundaries ? `\\b${frag.toLowerCase()}\\b` : frag.toLowerCase(), 'i')
                : new RegExp(enforce_word_boundaries ? `\\b${frag.source}\\b` : frag, 'i')
        )
        .map((frag) =>
            frag.source.includes('_') ? [frag, new RegExp(frag.source.replace(/_/g, ''), frag.flags)] : frag
        )
        .flat();

// prettier-ignore
export const button_id_fragments = normalizeFragments(['decline', 'reject', 'accept', 'agree', 'continue', 'yes', 'no', /personali(z|s)e/, 'manage', 'more_info'], true);
// prettier-ignore
export const dialog_id_fragments = normalizeFragments(['gdpr', 'consent', /cookie_settings/, 'iab', 'opt_in', 'user_choice', 'vendors?_list'], true);

// prettier-ignore
export const button_text_fragments = {
    clear_affirmative: normalizeFragments(['accept', 'agree', 'yes', 'akzeptieren', 'zustimmen', 'annehmen', 'ja'], true),
    hidden_affirmative: normalizeFragments(['ok', 'okay', 'next', 'continue', 'weiter', 'fortfahren', 'nein'], true),
    clear_negative: normalizeFragments(['decline', 'reject', 'refuse', 'no', 'widersprechen', 'ablehnen', 'verweigern'], true),
    hidden_negative: normalizeFragments([/customi(z|s)e/, 'more choices', 'settings', 'options', 'exit', 'cancel', 'einstellungen', 'optionen', 'anpassen', /schlie(ß|ss)en/, 'beenden', 'abbrechen'], true),
};

export const button_text_fragments_all = Object.values(button_text_fragments).flat();
// TODO: Continue the list.
export const dialog_text_fragments = normalizeFragments([
    /(we care about|comitted|respect)[^.]{0,10} (privacy|data protection)/,
    /(privacy|data protection) [^.]{0,35} important/,
    /can( always| later)? revoke[^.]{0,15} consent ?(at any time|later)?/,
    /(use|utilise|need|have|set|collect|ask)[^.]{0,25} (cookie|consent|tracking)/,
    /by (sign|logg|continu|creat|us|tapp|click|select|choos)ing [^.]{0,75},? (you|I) (agree|accept|consent|acknowledge|confirm)/,
    /(accept|agree|consent) [^.]{3,35} (privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/,
    /(accept|agree|consent) [^.]{3,35} processing [^.]{3,20} data/,
    /(learn|read|more|acknowledge) [^.]{2,40} (privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/,
    /have read( and understood)? [^.]{3,35} (privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/,

    /(Datenschutz|Privatsphäre) (ist uns wichtig|liegt uns am Herzen)/,
    /respektier[^.]{0,20} (Datenschutz|Privatsphäre)/,
    /wir nehmen[^.]{0,10} (Datenschutz|Privatsphäre) ernst/,
    /(kannst|können)[^.]{0,10} Einwilligung jederzeit[^.]{0,20} widerrufen/,
    /(benutz|verwend|nutz|brauch|benötig|hab|setz|sammel|frag)[^.]{0,25} (Cookie|Zustimmung|Einwilligung|Einverständnis|Tracking)/,
    /(mit|durch|bei|wenn) [^.]{2,30} (tipp|klick|(aus)?wähl)[^.]{2,65} (akzeptier|stimm|nimm|nehm|bestätig)/,
    /(akzeptier|stimm|nimm|nehm) [^.]{3,35} (Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)/,
    /(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information) [^.]{3,35} (akzeptier|stimm|nimm|nehm)/,
    /(akzeptier|stimm|nimm|nehm) [^.]{3,35} ((Verarbeit(ung|en) [^.]{3,20} Daten)|(Daten(-| )?[^.]{0,10}Verarbeit(ung|en)))/,
    /((Verarbeit(ung|en) [^.]{3,20} Daten)|(Daten(-| )?[^.]{0,10}Verarbeit(ung|en))) [^.]{3,35} (akzeptier|stimm|nimm|nehm)/,
    /(Informationen|mehr)( dazu)? [^.]{0,25}in [^.]{0,20} (Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)/,
    /(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information) [^.]{3,35} (gelesen|Kenntnis)/,
    /(Informationen|mehr)( dazu)? [^.]{0,30}in [^.]{0,25} (Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)/,
    /(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information) (gelesen|Kenntnis)/,
    /(mit|durch|bei|wenn) [^.]{2,30} (fortf(a|ä)hr|weitermach|anmeld|registrier|erstell|nutz|tipp|klick|(aus)?wähl)[^.]{2,65} (akzeptier|stimm|nimm|nehm|bestätig)/,
]);

// prettier-ignore
export const link_text_fragments = normalizeFragments([
    /(privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/,
    /(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)(e|en)?/
], true);

// prettier-ignore
export const keywords_regular = normalizeFragments([
    /third-party ad(vertising|s)?/, /(read|store) cookies/, /(ad(vertising|s)?|content|experience) personali(s|z)ation/, /personali(s|z)ed?[^.]{0,10} (ad(vertising|s)?|content|experience)/, /(ad(vertising|s)?|content) (measurement|performance)/, 'analytics', 'data processing purposes', 'audience insights', 'personal data', /user (behaviou?r|data)/, 'GDPR', 'data protection regulation', 'insufficient level of data protection', 'mobile identifiers', /(advertising|ad)-?ID/, /(necessary|essential|needed) cookies/, 'data processing', /(pseudo|ano)nymi(s|z)ed/, /(data protection|privacy) (settings|controls|preferences)/, 'legitimate interest', 'crash data', /(collect|transmit) (information|data)/,
    /Drittanbieter-?(Werbung|Anzeige|Werbeanzeige)/, /Cookies ((aus)?lesen|speichern)/, /personalisierte (Werbung|Anzeige|Werbeanzeige|Inhalt|Erfahrung)/, /(Werbungs?|Anzeigen|Werbeanzeigen|Inhalt(s|e)?|Erfahrungs)-?Personalisierung/, /(Werbungs?|Werbe|Anzeigen|Werbeanzeigen|Inhalt(s|e)?|Erfahrungs)-?(Messung|Performance|Leistung|Zahlen)/, 'Analysetools', /(Zwecke? der Verarbeitung|Verarbeitungszweck)/, 'Zielgruppenwissen', 'personenbezogen', /Nutz(er|ungs)(verhalten|daten)/, /DS-?GVO/, /Datenschutz-?Grundverordnung/, /gleiches? Datenschutzniveau/, /mobile (ID|Kennungs?)-?Nummer/, /(notwendige|erforderliche) Cookies/, /Datenverarbeitung|Verarbeitung (Deiner|Ihrer) Daten/, /(pseudonymisiert|anonymisiert)/, 'Datenschutzeinstellungen', /berechtigte(n|s)? Interesse/, /Crash-?(Daten|Bericht|Information)/, /(Daten|Informationen) (sammeln|übertragen|übermitteln)/
]);
// prettier-ignore
export const keywords_half = normalizeFragments([
    /(optimal|better) user experience/, 'European Court of Justice', /(without( any)?|effective) (legal|judicial) remedy/, 'geolocation data', 'third countries', 'IP address', 'app activity', 'consent', 'privacy', 'data protection', /\bprocess(ed|ing)?\b/,
    /(bessert?e|optimale) Nutz(er|ungs)erfahrung/, 'EuGH', /Europäische(r|n)? Gerichtshof/, /wirksame(r|n) Rechtsbehelf/, /(Standort|Geo)-?daten/, 'Drittländer', 'IP-Adresse', 'Aktivitätsdaten', 'Einwilligung', 'Datenschutz', 'Privatsphäre', /verarbeit(en|ung)/
]);
