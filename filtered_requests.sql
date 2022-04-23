drop view filtered_requests;

create view filtered_requests as
select name, platform, version, run_type, requests.*, regexp_replace(concat(requests.scheme, '://', requests.host, requests.path), '\?.+$', '') endpoint_url from apps
    join runs r on apps.id = r.app join requests on r.id = requests.run where

(
    platform = 'ios'
    and not requests.host = 'albert.apple.com' -- "Device activation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'captive.apple.com' -- "Internet connectivity validation for networks that use captive portals" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'gs.apple.com' -- (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'humb.apple.com' -- (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'static.ips.apple.com' -- (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'sq-device.apple.com' -- "eSIM activation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'tbsc.apple.com' -- (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'time-ios.apple.com' -- "Used by devices to set their date and time" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'time.apple.com' -- "Used by devices to set their date and time" (https://support.apple.com/en-us/HT210060)
    and not requests.host ~~ '%.push.apple.com' -- "Push notifications" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'gdmf.apple.com' -- "Used by an MDM server to identify which software updates are available to devices that use managed software updates" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'deviceenrollment.apple.com' -- "DEP provisional enrollment" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'deviceservices-external.apple.com' -- (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'identity.apple.com' -- "APNs certificate request portal" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'iprofiles.apple.com' -- "Hosts enrollment profiles used when devices enroll in Apple School Manager or Apple Business Manager through Device Enrollment" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'mdmenrollment.apple.com' -- "MDM servers to upload enrollment profiles used by clients enrolling through Device Enrollment in Apple School Manager or Apple Business Manager, and to look up devices and accounts" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'setup.icloud.com' -- "Required to log in with a Managed Apple ID on Shared iPad" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'vpp.itunes.apple.com' -- "MDM servers to perform operations related to Apps and Books, like assigning or revoking licenses on a device" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'appldnld.apple.com' -- "iOS updates" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'gg.apple.com' -- "iOS, tvOS, and macOS updates" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'mesu.apple.com' -- "Hosts software update catalogs" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'ns.itunes.apple.com' -- (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'updates-http.cdn-apple.com' -- (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'updates.cdn-apple.com' -- (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'xp.apple.com' -- (https://support.apple.com/en-us/HT210060)
    and not requests.host ~~ '%.itunes.apple.com' -- "Store content such as apps, books, and music" (https://support.apple.com/en-us/HT210060)
    and not requests.host ~~ '%.apps.apple.com' -- "Store content such as apps, books, and music" (https://support.apple.com/en-us/HT210060)
    and not requests.host ~~ '%.mzstatic.com' -- "Store content such as apps, books, and music" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'itunes.apple.com' -- (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'ppq.apple.com' -- "Enterprise App validation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'serverstatus.apple.com' -- "Content caching client public IP determination" (https://support.apple.com/en-us/HT210060)
    and not requests.host ~~ '%.appattest.apple.com' -- "App validation, Touch ID and Face ID authentication for websites" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'fba.apple.com' -- "Used by Feedback Assistant to file and view feedback" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'cssubmissions.apple.com' -- "Used by Feedback Assistant to upload files" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'diagassets.apple.com' -- "Used by Apple devices to help detect possible hardware issues" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'doh.dns.apple.com' -- "Used for DNS over HTTPS (DoH)" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'crl.apple.com' -- "Certificate validation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'crl.entrust.net' -- "Certificate validation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'crl3.digicert.com' -- "Certificate validation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'crl4.digicert.com' -- "Certificate validation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'ocsp.apple.com' -- "Certificate validation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'ocsp.digicert.com' -- "Certificate validation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'ocsp.entrust.net' -- "Certificate validation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'ocsp.verisign.net' -- "Certificate validation" (https://support.apple.com/en-us/HT210060)
    and not requests.host = 'valid.apple.com' -- "Certificate validation" (https://support.apple.com/en-us/HT210060)

    and not requests.host = 'ocsp2.apple.com' -- OCSP
    and not requests.host ~~ '%smoot.apple.com' -- Spotlight (https://apple.stackexchange.com/a/157495)
    and not requests.host = 'configuration.apple.com' -- CloudKit/iCloud (https://en.wikipedia.org/wiki/CloudKit)
    and not requests.host = 'configuration.ls.apple.com'
    and not requests.host ~~ 'gspe%-ssl.ls.apple.com' -- Apple Maps (https://developer.apple.com/forums/thread/99015)
    and not requests.host ~~ 'gsp%-ssl.ls.apple.com' -- Apple Maps (https://developer.apple.com/forums/thread/99015)
    and not requests.host = 'weather-data.apple.com' -- Weather data
    and not requests.host = 'pancake.apple.com'
    and not requests.host = 'token.safebrowsing.apple' -- Safe browsing
    and not requests.host = 'apple-finance.query.yahoo.com' -- Finance widget
    and not requests.host ~~ 'p%-%.icloud.com' -- iCloud calendar, contacts
    and not requests.host = 'keyvalueservice.icloud.com' -- iCloud keychain (https://speakerdeck.com/belenko/icloud-keychain-and-ios-7-data-protection, https://github.com/prabhu/iCloud)
    and not requests.host = 'gs-loc.apple.com' -- Location services (https://apple.stackexchange.com/questions/63540/what-is-gs-loc-apple-com, https://github.com/zadewg/GS-LOC)
    and not requests.host = 'gateway.icloud.com'
    and not requests.host = 'metrics.icloud.com'
    and not requests.host = 'csig.apple.com'
    and not requests.host = 'calendars.icloud.com'
)

or

(
    platform = 'android'
    and not (requests.host = 'android.clients.google.com' and requests.path = '/c2dm/register3')
    and not (requests.host = 'android.googleapis.com' and requests.path = '/auth/devicekey')
    and not (requests.host ~~ '%.googleapis.com' and requests.path ~~ '/google.internal%')
    and not (requests.host ~~ 'www.googleapis.com' and requests.path ~~ '/androidantiabuse/%')
    and not (requests.host ~~ 'www.googleapis.com' and requests.path ~~ '/androidcheck/v1/attestations%')
    and not (requests.host ~~ 'play.googleapis.com' and requests.path = '/log/batch')
    and not (requests.host ~~ 'www.googleapis.com' and requests.path ~~ '/experimentsandconfigs/%')
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
    and not (requests.host = 'ssl.google-analytics.com' and requests.content ~ 'UA-61414137-1')
    and not (requests.host = 'www.googletagmanager.com' and requests.content ~ 'GTM-K9CNX3')
    and not requests.host = 'accounts.google.com'
    and not requests.host = 'safebrowsing.googleapis.com'
    and not requests.path ~ '/v1/projects/chime-sdk/installations'
)

-- On Android, plenty of system apps also transmit to app-measurement.com. This way, we only filter out those caused by our current app.
and not (requests.host = 'app-measurement.com' and not encode(requests.content_raw, 'escape') like concat('%', apps.name, '%'));

alter table filtered_requests owner to ma;

-- The filters for Android are based on the work for the "Do they track? Automated analysis of Android apps for privacy
-- violations" research project (https://benjamin-altpeter.de/doc/presentation-android-privacy.pdf). The initial version
-- is licensed under the following license:
--
-- The MIT License
--
-- Copyright 2020 – 2021 Malte Wessels and Benjamin Altpeter
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to deal
-- in the Software without restriction, including without limitation the rights
-- to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
-- copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in all
-- copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
-- OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
-- SOFTWARE.
