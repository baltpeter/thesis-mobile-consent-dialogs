# Discussion

## Comparison with Results for the Web

* https://arxiv.org/pdf/2001.02479.pdf

## Limitations

* No interaction with apps beyond consent dialog (e.g. first-run wizards not considered)
* Only considers text that is machine-readable and available to Appium (e.g. games are often essentially images that Appium can't "read")
* Only DE and EN supported
* Appium can only access a very limited amount of element attributes
* Analysis provides lower bound
* Launching TODO % of Android apps failed due to certificate pinning bypass
* Apps can trivally detect emulator/root/jailbreak, some change their behaviour based on that (e.g. make it impossible to use app)
