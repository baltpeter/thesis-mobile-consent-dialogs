# Informed Consent? A Study of “Consent Dialogs” on Android and iOS

> Source code, data, presentation, and notes for my [master’s thesis on consent dialogs in mobile apps on Android and iOS](https://benjamin-altpeter.de/doc/thesis-consent-dialogs.pdf)

Consent dialogs have become ubiquitous with seemingly every website and app pleading users to agree to their personal data being processed and their behaviour being tracked, often with the help of tens or even hundreds of third-party companies. They are an effort by website and app publishers to comply with data protection legislation like the GDPR, which imposes strict limits on how companies can process data. Previous research has established that companies often apply dark patterns to illegally nudge users into agreeing and that at the same time tracking is more common than ever with both websites and apps regularly automatically transmitting telemetry data.

But so far, there has been almost no research into consent dialogs on mobile. For my [master’s thesis](https://benjamin-altpeter.de/doc/thesis-consent-dialogs.pdf), I studied consent dialogs on Android and iOS in an automated and dynamic manner, analysing 4,388 popular apps from both platforms. I identified different types of consent elements in the apps and analysed their prevalence. I also identified dark patterns and violations by the apps based on a list of criteria for a legally compliant consent dialog that I have compiled. Finally, I measured the effect of the user’s choice in the consent dialog by comparing the traffic from before any interaction with the traffic after accepting and rejecting the dialog and analysing contacted trackers and transmitted data types. The results show that more than 90 % of consent dialogs implement at least one dark pattern and that a majority of apps transmits tracking data regardless of consent status.

## Setup

### Preparation on macOS

* Run `brew install postgresql` to be able to install `psycopg2` later ([ref](https://github.com/psycopg/psycopg2/issues/1286#issuecomment-914286206)).
* Install `libimobiledevice`: `brew install libimobiledevice ideviceinstaller`
* Install `sshpass`: `brew install esolitos/ipa/sshpass`
* SSH into the iDevice manually once to add it to the list of known hosts.

### Preparation for all systems

```sh
npm install -g appium appium-doctor
# Run `appium-doctor --android` or `appium-doctor --ios` and resolve the issues.

git clone https://github.com/baltpeter/thesis-mobile-consent-dialogs
cd thesis-mobile-consent-dialogs
yarn

python3 -m venv venv
source venv/bin/activate
pip install mitmproxy frida-tools objection python-dotenv psycopg2-binary

cd src
cp .env.sample .env
# Edit the values accordingly.
nano .env
```

### Steps for setting up Appium under iOS

based on: https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/ and https://makaka.org/unity-tutorials/test-ios-app-without-developer-account

0. Create an Apple developer account (free is fine) and use that to log into XCode.
1. Connect the iPhone via USB.
2. Start *XCode*. In the menu bar, click *Window* and *Devices and Simulators*. Ensure the iPhone is available there.
3. In a terminal, start `appium`.
4. Follow the steps at https://appium.io/docs/en/drivers/ios-xcuitest-real-devices/#full-manual-configuration (full manual configuration).
5. Open *Appium Inspector* and create a session with the following desired capabilities to test (adapted to your configuration):

  ```json
  {
    "appium:xcodeOrgId": "<org-id>",
    "appium:xcodeSigningId": "Apple Development",
    "appium:udid": "auto",
    "platformName": "iOS",
    "appium:app": "/path/to/app.ipa",
    "appium:automationName": "XCUITest",
    "appium:deviceName": "iPhone",
    "appium:updatedWDABundleId": "tld.your-domain.WebDriverAgentRunner"
  }
  ```

  Replace `appium:app` with the path to any IPA, `appium:updatedWDABundleId` with the ID chosen in the previous step, and `appium:xcodeOrgId` with the personal team ID. To find that, open the *Keychain Access* app. On the left, select *login* under *Default Keychains*, then choose *My Certificates* in the top bar. Doubleclick the correct certificate. The ID is listed under *Organizational Unit*.
6. Use the latter two values for running the analysis.

### Device preparation

#### iOS

* Jailbreak using [checkra1n](https://checkra.in/) (only works on iOS 14).
* Enable SSH server.
    * Install packages [OpenSSH](https://cydia.saurik.com/package/openssh/), [Open](http://cydia.saurik.com/package/com.conradkramer.open/), [Sqlite3](http://apt.bingner.com/debs/1443.00/sqlite3_3.24.0-1_iphoneos-arm.deb) from Cydia.
    * Connect using `root@<ip>`, password `alpine`.
* Set the following settings:
    * General
        * Background App Refresh: off (to hopefully minimize background network traffic)
        * Software Update
            * Automatic Updates
                * Install iOS Updates: off
                * Download iOS Updates: off
    * Display & Brightness
        * Auto-Lock: never
    * Privacy
        * Location Services
            * Location Services: on
        * Analytics & Improvements
            * Share iPhone Analytics: off
        * Apple Advertising
            * Personalised Ads: on (default)
    * App Store
        * Automatic Downloads
            * Apps: off
            * App Updates: off
* Install [Activator](https://cydia.saurik.com/package/libactivator/).
* Setup mitmproxy: https://www.andyibanez.com/posts/intercepting-network-mitmproxy/#physical-ios-devices
* Install [SSL Kill Switch 2](https://github.com/nabla-c0d3/ssl-kill-switch2) (https://steipete.com/posts/jailbreaking-for-ios-developers/#ssl-kill-switch)
    * Install Debian Packager, Cydia Substrate, PreferenceLoader, PullToRespring, and Filza from Cydia.
    * Download latest release: https://github.com/nabla-c0d3/ssl-kill-switch2/releases
    * In Filza, go to `/private/var/mobile/Library/Mobile Documents/com~apple~CloudDocs/Downloads` and install.
    * Respring by opening Settings and pulling down.
    * Enable in Settings under SSL Kill Switch 2.
* Install [Frida](https://frida.re/docs/ios/#with-jailbreak).
* Uninstall all third-party apps that are not absolutely necessary.
* Turn on Bluetooth.

#### Android

* Make sure to use an x86_64 emulator (Android 11).
* Uninstall unnecessary Google apps to avoid their background traffic:
  ```sh
  adb shell 'pm uninstall --user 0 com.android.chrome'
  adb shell 'pm uninstall --user 0 com.google.android.apps.docs'
  adb shell 'pm uninstall --user 0 com.google.android.apps.maps'
  adb shell 'pm uninstall --user 0 com.google.android.apps.messaging'
  adb shell 'pm uninstall --user 0 com.google.android.apps.photos'
  adb shell 'pm uninstall --user 0 com.google.android.apps.pixelmigrate'
  adb shell 'pm uninstall --user 0 com.google.android.apps.wellbeing'
  adb shell 'pm uninstall --user 0 com.google.android.apps.youtube.music'
  adb shell 'pm uninstall --user 0 com.google.android.gm'
  adb shell 'pm uninstall --user 0 com.google.android.googlequicksearchbox'
  adb shell 'pm uninstall --user 0 com.google.android.videos'
  adb shell 'pm uninstall --user 0 com.google.android.youtube'
  adb shell 'pm uninstall --user 0 com.google.mainline.telemetry'
  ```
* Disable captive portal checks to further reduce background noise:
  ```sh
  adb shell 'settings put global captive_portal_detection_enabled 0'
  adb shell 'settings put global captive_portal_server localhost'
  adb shell 'settings put global captive_portal_mode 0'
  ```
* Install the mitmproxy certificate as root CA (emu needs to be started with `-writable-system`):
  ```sh
  # Yields <hash>.
  openssl x509 -inform PEM -subject_hash_old -in ~/.mitmproxy/mitmproxy-ca-cert.pem | head -1
  cp ~/.mitmproxy/mitmproxy-ca-cert.pem <hash>.0
  
  adb root
  adb shell avbctl disable-verification
  adb disable-verity
  adb reboot
  adb root
  adb remount
  
  adb push <hash>.0 /sdcard/
  adb shell 'mv /sdcard/<hash>.0 /system/etc/security/cacerts/'
  adb shell 'chmod 644 /system/etc/security/cacerts/<hash>.0'
  adb reboot
  ```
* Install Frida on the emulator (note that the version must match the one on the host):
  ```sh
  wget https://github.com/frida/frida/releases/download/15.1.12/frida-server-15.1.12-android-x86_64.xz
  7z x frida-server-15.1.12-android-x86_64.xz
  adb push frida-server-15.1.12-android-x86_64 /data/local/tmp/frida-server
  adb shell 'chmod 777 /data/local/tmp/frida-server'
  
  adb root
  adb shell 'nohup /data/local/tmp/frida-server >/dev/null 2>&1 &'
  # Should have `frida-server`.
  frida-ps -U | grep frida
  ```

### Honey data

This is the honey data that I set in my analysis. You should probably change it. Remember to also change [query.ts](src/common/query.ts) accordingly.

* Contact: `JGKfozntbF TBFFZbBYea`, 0155 57543434, `RYnlSPbEYh@bn.al`, `https://q8phlLSJgq.bn.al`, `N2AsWEMI5D 565, 859663 p0GdKDTbYV`
* Messages: `9FBqD2CNIJ` (to|from) +49 155 75734343
* Calls from and to +49 155 75734343 (Android only)
* Calendar: `fWAs4GFbpN`, at `urscf2178L`, 2022-08-14T08:56 (iOS only)
* Reminder: `b5jHg3Eh1k`, `HQBOdx4kx2` (scheduled for 2022-08-02T13:38) (iOS only)
* Health details: Name `DkwIXobsJN t5TfTlezmn`, DOB 1973-05-15, female, height 146cm, weight 108.5kg (iOS only)
* Home data: Rooms `bEZf1h06j1`, `DX7BgPtH99` (basement); second home `g1bVNue3On` (iOS only)
* Device name: `R2Gl5OLv20`
* Note: `S0Ei7sFP9b` (iOS only)
* Phone number: +49 155 85834346 (Android only)
* Location: Schreinerweg 6, 38126 Braunschweig; 52.235288, 10.564235
* Apple ID (iOS only)
* Clipboard: `LDDsvPqQdT`

## LICENSE

This code is licensed under the MIT license, see the [`LICENSE`](LICENSE) file for details.

## Status

This repository is archived in the state it was in when I submitted my thesis. I will not be updating it any further. However, I am working together with [@zner0L](https://github.com/zner0L) on a follow-up project. As a part of this project, we will also make sure to extract reusable libraries and tools from this research code and document them more thouroughly. Follow [me](https://mastodon.social/@baltpeter) and [datarequests.org](https://mastodon.social/@datarequestsorg) on Mastodon to stay up to date on that.
