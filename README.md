# unapkm

## 2021.01 Update
This tool is now no longer required thankfully, as APKMirror is serving exclusively decrypted APKM files (these are just regular ZIP files)!

See https://github.com/android-police/apkmirror-public/issues/119 for more discussion.

I've added a check to test whether the file provided to UnApkm is a regular zip file; this tool will still work on any old downloads of .apkm's you have!

## Old introduction

There's a new split apk file format in town (apkm - https://www.androidpolice.com/2020/03/24/apkmirror-installer-for-android-now-in-public-beta-lets-you-install-app-bundles-and-apks/), but it's encrypted.

This is not helpful for modding or anything else really. And the only installer for it makes you watch ads/pay a subcription just to install otherwise free apps (? even play store doesn't do this - it seems a bit spammy and these aren't even their own apps they're hosting!)

This tool decrypts them into a more standard APKS format that can be opened with 7zip so you can install it yourself with https://github.com/Aefyr/SAI or another open source tool - installing apps shouldn't be a proprietary feature!

```
Usage:
  java -jar unapkm.jar <path/to/apkm> <path/to/output>

```
## Download

Here: https://github.com/souramoo/unapkm/releases
