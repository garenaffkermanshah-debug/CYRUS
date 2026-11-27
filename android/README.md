# CYRUS Android wrapper

This is an installable Android WebView shell for the live CYRUS web app at https://cyrus.ethiodeploy.app/.

It requires internet access and is not an offline/native client. Build the debug APK with:

```bash
gradle --no-daemon assembleDebug
```

APK output: `app/build/outputs/apk/debug/app-debug.apk`

Build workflow is configured in GitHub Actions and uploads the debug APK as `CYRUS-debug-APK`.
