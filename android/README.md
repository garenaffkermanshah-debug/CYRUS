# CYRUS Android wrapper

This is an installable Android WebView shell for the CYRUS web app at https://cyrus.cyrus.prod.page/. The launch URL is configured in `MainActivity.java`.

It requires internet access and is not an offline/native client. If the deployment hostname changes, update `HOME` in `MainActivity.java` and rebuild the APK. Build the debug APK with:

```bash
gradle --no-daemon assembleDebug
```

APK output: `app/build/outputs/apk/debug/app-debug.apk`

Build workflow is configured in GitHub Actions and uploads the debug APK as `CYRUS-debug-APK`.
