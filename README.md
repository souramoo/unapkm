# unapkm
There's a new split apk file format in town (apkm - https://www.androidpolice.com/2020/03/24/apkmirror-installer-for-android-now-in-public-beta-lets-you-install-app-bundles-and-apks/), but it's encrypted.

This is not helpful for modding or anything else really. And the only installer for it makes you watch ads/pay a subcription just to install otherwise free apps (? even play store doesn't do this - it seems a bit spammy and these aren't even their own apps they're hosting!)

This tool decrypts them into a more standard APKS format that can be opened with 7zip so you can install it yourself with https://github.com/Aefyr/SAI or another open source tool - installing apps shouldn't be a proprietary feature!

```
Usage:
  java -jar unapkm.jar <path/to/apkm> <path/to/output>

```
## Download

Here: https://github.com/souramoo/unapkm/releases
