\appendix

# Appendix

## Additional Figures and Tables {#sec:appendix-figures-tables}

| ID                                | Label in Settings      | Granted?       |
|-----------------------------------|------------------------|----------------|
| `kTCCServiceCalendar`             | Calendars              | granted        |
| `kTCCServiceAddressBook`          | Contacts               | granted        |
| `kTCCServiceReminders`            | Reminders              | granted        |
| `kTCCServicePhotos`               | Photos                 | granted        |
| `kTCCServiceMediaLibrary`         | Media & Apple Music    | granted        |
| `kTCCServiceBluetoothAlways`      | Bluetooth              | granted        |
| `kTCCServiceMotion`               | Motion & Fitness       | granted        |
| `kTCCServiceWillow`               | Home Data              | granted        |
| `kTCCServiceExposureNotification` | Exposure Notifications | granted        |
| `kTCCServiceLiverpool`            | *no visible effect*    | granted        |
| `kTCCServiceUbiquity`             | *no visible effect*    | granted        |
| `kTCCServiceCamera`               | Camera                 | denied         |
| `kTCCServiceMicrophone`           | Microphone             | denied         |
| `kTCCServiceUserTracking`         | Allow Tracking         | denied         |

:   List of the permissions we set on iOS. The labels were determined by setting the permissions on a test app and observing the change in the Settings app. {#tbl:appendix-ios-permissions}


| iOS                          | Android                              |
|------------------------------|--------------------------------------|
|                              | Auto & Vehicles                      |
|                              | Beauty                               |
| Books; Reference             | Books & Reference                    |
| Business                     | Business                             |
| Catalogues                   |                                      |
|                              | Comics                               |
|                              | Dating                               |
| Developer Tools              |                                      |
| Education                    | Education                            |
| Entertainment                | Entertainment                        |
|                              | Events                               |
| Finance                      | Finance                              |
| Food & Drink                 | Food & Drink                         |
| Games                        | Games                                |
| Graphics & Design            | Art & Design                         |
| Health & Fitness             | Health & Fitness                     |
|                              | House & Home                         |
|                              | Kids                                 |
|                              | Libraries & Demo                     |
| Lifestyle                    | Lifestyle                            |
| Medical                      | Medical                              |
| Music                        | Music & Audio                        |
| Navigation                   | Maps & Navigation                    |
| News; Magazines & Newspapers | News & Magazines                     |
|                              | Parenting                            |
|                              | Personalization                      |
| Photo & Video                | Photography; Video Players & Editors |
| Productivity                 | Productivity                         |
| Shopping                     | Shopping                             |
| Social Networking            | Social; Communication                |
| Sports                       | Sports                               |
| Stickers                     |                                      |
| Travel                       | Travel & Local                       |
| Utilities                    | Tools                                |
|                              | Watch apps                           |
| Weather                      | Weather                              |

:   Matching of the categories on the App Store (iOS) and Google Play Store (Android). Multiple categories in a single row are delimited by semicolons. Not every category is available on both platforms. {#tbl:appendix-categories}

## SQL Query to Create the Background Request Filter View {#sec:appendix-filtered-requests-sql}

We use the following SQL view to filter out background noise from the operating systems. We compiled the filters by recording the idle traffic of both platforms for several days and then writing queries to filter out all traffic.

```sql
create view filtered_requests as
select name, platform, version, run_type, requests.*,
  regexp_replace(concat(
    requests.scheme, '://', requests.host, requests.path), '\?.+$', ''
  ) endpoint_url from apps
join runs r on apps.id = r.app join requests on r.id = requests.run where

(
  platform = 'ios'
  and not requests.host = 'albert.apple.com' and not requests.host = 'captive.apple.com'
  and not requests.host = 'gs.apple.com'  and not requests.host = 'humb.apple.com' 
  and not requests.host = 'sq-device.apple.com' and not requests.host = 'tbsc.apple.com'
  and not requests.host = 'time-ios.apple.com' and not requests.host = 'time.apple.com'
  and not requests.host ~~ '%.push.apple.com' and not requests.host = 'gdmf.apple.com'
  and not requests.host = 'gg.apple.com' and not requests.host = 'identity.apple.com'
  and not requests.host = 'iprofiles.apple.com' and not requests.host = 'mesu.apple.com'
  and not requests.host = 'appldnld.apple.com' and not requests.host = 'ppq.apple.com'
  and not requests.host = 'xp.apple.com' and not requests.host ~~ '%.itunes.apple.com'
  and not requests.host = 'doh.dns.apple.com' and not requests.host = 'crl.apple.com'
  and not requests.host = 'crl.entrust.net' and not requests.host = 'crl3.digicert.com'
  and not requests.host = 'crl4.digicert.com' and not requests.host = 'ocsp.apple.com'
  and not requests.host = 'ocsp.digicert.com' and not requests.host = 'ocsp.entrust.net'
  and not requests.host = 'ocsp.verisign.net' and not requests.host = 'valid.apple.com'
  and not requests.host = 'ocsp2.apple.com' and not requests.host ~~ '%smoot.apple.com'
  and not requests.host = 'ns.itunes.apple.com' and not requests.host = 'fba.apple.com'
  and not requests.host ~~ '%.apps.apple.com' and not requests.host ~~ '%.mzstatic.com'
  and not requests.host = 'itunes.apple.com' and not requests.host = 'setup.icloud.com'
  and not requests.host = 'pancake.apple.com' and not requests.host = 'csig.apple.com'
  and not requests.host = 'gs-loc.apple.com' and not requests.host ~~ 'p%-%.icloud.com'
  and not requests.host = 'deviceenrollment.apple.com'
  and not requests.host = 'deviceservices-external.apple.com'
  and not requests.host = 'static.ips.apple.com'
  and not requests.host = 'mdmenrollment.apple.com'
  and not requests.host = 'vpp.itunes.apple.com'
  and not requests.host = 'updates-http.cdn-apple.com'
  and not requests.host = 'updates.cdn-apple.com'
  and not requests.host = 'serverstatus.apple.com'
  and not requests.host ~~ '%.appattest.apple.com'
  and not requests.host = 'cssubmissions.apple.com'
  and not requests.host = 'diagassets.apple.com'
  and not requests.host = 'configuration.apple.com'
  and not requests.host = 'configuration.ls.apple.com'
  and not requests.host ~~ 'gspe%-ssl.ls.apple.com'
  and not requests.host ~~ 'gsp%-ssl.ls.apple.com'
  and not requests.host = 'weather-data.apple.com'
  and not requests.host = 'token.safebrowsing.apple'
  and not requests.host = 'apple-finance.query.yahoo.com'
  and not requests.host = 'keyvalueservice.icloud.com'
  and not requests.host = 'gateway.icloud.com'
  and not requests.host = 'metrics.icloud.com'
  and not requests.host = 'calendars.icloud.com'
)

or

(
  platform = 'android'
  and not (requests.host = 'android.clients.google.com'
           and requests.path = '/c2dm/register3')
  and not
    (requests.host = 'android.googleapis.com' and requests.path = '/auth/devicekey')
  and not (requests.host ~~ '%.googleapis.com' and requests.path ~~ '/google.internal%')
  and not
    (requests.host ~~ 'www.googleapis.com' and requests.path ~~ '/androidantiabuse/%')
  and not (requests.host ~~ 'www.googleapis.com' and
          requests.path ~~ '/androidcheck/v1/attestations%')
  and not (requests.host ~~ 'play.googleapis.com' and requests.path = '/log/batch')
  and not (requests.host ~~ 'www.googleapis.com'
           and requests.path ~~ '/experimentsandconfigs/%')
  and not requests.host = '172.217.19.74'
  and not (requests.host ~~ 'firebaseinstallations.googleapis.com' and
          requests.path ~~ '/v1/projects/google.com%')
  and not (requests.host ~~ 'firebaseinstallations.googleapis.com' and
          requests.path ~~ '/v1/projects/metal-dimension-646%')
  and not (requests.host ~~ 'firebaseinstallations.googleapis.com' and
          requests.path ~~ '/v1/projects/zillatest-20296%')
  and not (requests.host ~~ '%gvt1.com' and requests.path ~~ '/edgedl/%')
  and not requests.host ~~ 'update.googleapis.com'
  and not (requests.host ~~ 'www.gstatic.com' and requests.path ~~ '/android%')
  and not (requests.host = 'www.google.com' and requests.path = '/loc/m/api')
  and not (requests.host = 'ssl.gstatic.com' and requests.path ~ '/suggest-dev/yt')
  and not (requests.host = 'android.googleapis.com' and requests.path = '/checkin')
  and not (requests.host = 'www.gstatic.com' and requests.path ~ '/commerce/wallet')
  and not (requests.host = 'app-measurement.com' and
          requests.path ~ '/config/app/1%3A357317899610%3Aandroid%3A4765c0ded882c665')
  and not (requests.host = 'app-measurement.com' and
          requests.path ~ '/config/app/1%3A1086610230652%3Aandroid%3A131e4c3db28fca84')
  and not (requests.host = 'ssl.google-analytics.com'
           and requests.content ~ 'UA-61414137-1')
  and not (requests.host = 'www.googletagmanager.com'
           and requests.content ~ 'GTM-K9CNX3')
  and not requests.host = 'accounts.google.com'
  and not requests.host = 'safebrowsing.googleapis.com'
  and not requests.path ~ '/v1/projects/chime-sdk/installations'
)

-- On Android, plenty of system apps also transmit to app-measurement.com. This way, we
-- only filter out those caused by our current app.
and not (requests.host = 'app-measurement.com'
         and not encode(requests.content_raw, 'escape') 
           like concat('%', apps.name, '%'));
```

## Regexes Used for Detecting Consent Elements {#sec:appendix-detector-regexes}

We use the following regexes and strings to find clear "accept" buttons:

```js
/(accept|agree|allow|consent|permit) and continue/, 'accept', 'agree', 'allow',
'consent', 'permit', /(select|choose) all/, 'yes',

/(akzeptieren?|zustimmen|zulassen|annehmen|erlauben?|einwilligen|genehmigen?) und
  weiter/, /akzeptieren?/, 'zustimmen', 'zulassen', 'annehmen', /erlauben?/,
'einwilligen', /genehmigen?/, /alle (aus)?wählen/, /stimm[^.]{0,4} zu/,
/nehm[^.]{0,4} an/, /willig[^.]{0,4} ein/, 'ja'
```

We use the following strings to find ambiguous "accept" buttons:

```js
'ok', 'okay', 'got it', 'confirm', 'next', 'continue',
'yes, continue to see relevant ads',

'weiter', 'fortfahren', 'bestätigen'
```

We use the following regexes and strings to find clear "reject" buttons:

```js
'disagree', 'decline', 'reject', 'refuse', 'deny', /opt(- )?out/, 'no',
/(do not|don't|without) (accept|agree|allow|consent|permit)(ing)?/,
/no,? thanks?( you)?/, 'i want to opt out',

/widersprechen?/, 'ablehnen', /verweiger(n|e)/, 'nein',
/nicht (akzeptieren?|zustimmen|zulassen|annehmen|erlauben?|einwilligen|genehmigen?)/,
/ohne (akzept|zustimm|zulass|annehm|erlaub|einwillig|genehmig)/, /lehn[^.]{0,4} ab/,
/nein,? danke/
```

We use the following regexes and strings to find ambiguous "reject" buttons:

```js
/customi(z|s)e/, /personali(z|s)e/, /more (choices|details|info|information)/,
'settings', 'options', 'preferences', 'configure',
/(adjust|change|manage|view|show|more)[^.]{0,12}
    (details|settings|options|preferences|cookies|choices)/,
/(confirm|save)[^.]{0,8} selection/, 'later', 'skip', 'exit', 'cancel',
/(learn|read) more/, 'not now', 'no, see ads that are less relevant',

'anpassen', 'personalisieren', 'einstellungen', 'einstellen', 'konfigurieren',
'optionen', /(details|einstellungen|optionen|cookies|auswahl)[^.]{0,5}
    (anpassen|ändern|verwalten)/, /mehr (details|infos|information)/,
'details anzeigen', 'anpassen', /auswahl (bestätigen|speichern)/, 'später',
/schlie(ß|ss)en/, 'beenden', 'abbrechen', /mehr (erfahren|lesen)/, 'jetzt nicht',
'überspringen'
```

The following negator regexes and strings prevent an element from being classified as an affirmative button:

```js
'disagree', 'decline', 'reject', 'refuse', 'deny', /opt(- )?out/, 'no', "don't", 'not',

/widersprechen?/, 'ablehnen', /verweiger(n|e)/, 'nein', 'nicht', 'kein'
```

We use the following regexes to detect dialogs and notices:

```js
/(we care about|comitted|respect)[^.]{0,10} (privacy|data protection)/,
/(privacy|data protection) [^.]{0,35} important/,
/can( always| later)? revoke[^.]{0,15} consent ?(at any time|later)?/,
/(use|utilise|need|have|set|collect|ask)[^.]{0,25} (cookie|consent|tracking)/,
/by (sign|logg|continu|creat|us|tapp|click|select|choos)ing [^.]{0,75},?
    (you|I) (agree|accept|consent|acknowledge|confirm)/,
/(accept|agree|consent) [^.]{3,35} (privacy|cookie|data protection|GDPR)
    (policy|notice|information|statement)/,
/(accept|agree|consent) [^.]{3,35} processing [^.]{3,20} data/,
/(learn|read|more|acknowledge) [^.]{2,40} (privacy|cookie|data protection|GDPR)
    (policy|notice|information|statement)/,
/have read( and understood)? [^.]{3,35} (privacy|cookie|data protection|GDPR)
    (policy|notice|information|statement)/,

/(Datenschutz|Privatsphäre) (ist uns wichtig|liegt uns am Herzen)/,
/respektier[^.]{0,20} (Datenschutz|Privatsphäre)/,
/wir nehmen[^.]{0,10} (Datenschutz|Privatsphäre) ernst/,
/(kannst|können)[^.]{0,10} Einwilligung jederzeit[^.]{0,20} widerrufen/,
/(benutz|verwend|nutz|brauch|benötig|hab|setz|sammel|frag)[^.]{0,25}
    (Cookie|Zustimmung|Einwilligung|Einverständnis|Tracking)/,
/(mit|durch|bei|wenn) [^.]{2,30} (tipp|klick|(aus)?wähl)[^.]{2,65}
    (akzeptier|stimm|nimm|nehm|bestätig)/,
/(akzeptier|stimm|nimm|nehm) [^.]{3,35}
    (Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)/,
/(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information) [^.]{3,35}
    (akzeptier|stimm|nimm|nehm)/,
/(akzeptier|stimm|nimm|nehm) [^.]{3,35}
    ((Verarbeit(ung|en) [^.]{3,20} Daten)|(Daten(-| )?[^.]{0,10}Verarbeit(ung|en)))/,
/((Verarbeit(ung|en) [^.]{3,20} Daten)|(Daten(-| )?[^.]{0,10}Verarbeit(ung|en)))
    [^.]{3,35} (akzeptier|stimm|nimm|nehm)/,
/(Informationen|mehr)( dazu)? [^.]{0,25}in [^.]{0,20}
    (Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)/,
/(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)
    [^.]{3,35} (gelesen|Kenntnis)/,
/(Informationen|mehr)( dazu)? [^.]{0,30}in [^.]{0,25}
    (Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)/,
/(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)
    (gelesen|Kenntnis)/,
/(mit|durch|bei|wenn) [^.]{2,30}
    (fortf(a|ä)hr|weitermach|anmeld|registrier|erstell|nutz|tipp|klick|(aus)?wähl)
        [^.]{2,65} (akzeptier|stimm|nimm|nehm|bestätig)/,
```

We use the following regexes to detect privacy policy links:

```js
/(privacy|cookie|data protection|GDPR) (policy|notice|information|statement)/,

/(Datenschutz|Cookie|DSGVO|Privatsphäre)-?(hinweis|erklärung|information)(e|en)?/
```

The following keywords are worth one point:

```js
/third-party ad(vertising|s)?/, /(read|store) cookies/,
/(ad(vertising|s)?|content|experience) personali(s|z)ation/,
/personali(s|z)ed?[^.]{0,10} (ad(vertising|s)?|content|experience)/,
/(ad(vertising|s)?|content) (measurement|performance)/, 'analytics',
'data processing purposes', 'audience insights', 'personal data',
/user (behaviou?r|data)/, 'GDPR', 'data protection regulation',
'insufficient level of data protection', 'mobile identifiers', /(advertising|ad)-?ID/,
/(necessary|essential|needed) cookies/, 'data processing', /(pseudo|ano)nymi(s|z)ed/,
/(data protection|privacy) (settings|controls|preferences)/, 'legitimate interest',
'crash data', /(collect|transmit) (information|data)/,

/Drittanbieter-?(Werbung|Anzeige|Werbeanzeige)/, /Cookies ((aus)?lesen|speichern)/,
/personalisierte (Werbung|Anzeige|Werbeanzeige|Inhalt|Erfahrung)/,
/(Werbungs?|Anzeigen|Werbeanzeigen|Inhalt(s|e)?|Erfahrungs)-?Personalisierung/,
/(Werbungs?|Werbe|Anzeigen|Werbeanzeigen|Inhalt(s|e)?|Erfahrungs)-?
    (Messung|Performance|Leistung|Zahlen)/, 'Analysetools',
/(Zwecke? der Verarbeitung|Verarbeitungszweck)/, 'Zielgruppenwissen', 'personenbezogen',
/Nutz(er|ungs)(verhalten|daten)/, /DS-?GVO/, /Datenschutz-?Grundverordnung/,
/gleiches? Datenschutzniveau/, /mobile (ID|Kennungs?)-?Nummer/,
/(notwendige|erforderliche) Cookies/,
/Datenverarbeitung|Verarbeitung (Deiner|Ihrer) Daten/, /(pseudonymisiert|anonymisiert)/,
'Datenschutzeinstellungen', /berechtigte(n|s)? Interesse/,
/Crash-?(Daten|Bericht|Information)/,
/(Daten|Informationen) (sammeln|übertragen|übermitteln)/
```

The following keywords are worth half a point:

```js
/(optimal|better) user experience/, 'European Court of Justice',
/(without( any)?|effective) (legal|judicial) remedy/, 'geolocation data',
'third countries', 'IP address', 'app activity', 'consent', 'privacy',
'data protection', /\bprocess(ed|ing)?\b/,

/(bessert?e|optimale) Nutz(er|ungs)erfahrung/, 'EuGH', /Europäische(r|n)? Gerichtshof/,
/wirksame(r|n) Rechtsbehelf/, /(Standort|Geo)-?daten/, 'Drittländer', 'IP-Adresse',
'Aktivitätsdaten', 'Einwilligung', 'Datenschutz', 'Privatsphäre', /verarbeit(en|ung)/
```
