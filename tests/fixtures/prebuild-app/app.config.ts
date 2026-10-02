import type { ConfigContext, ExpoConfig } from 'expo/config';

const IS_DEV = process.env.APP_VARIANT === 'development';

export default ({ config }: ConfigContext): ExpoConfig => ({
  ...config,
  name: IS_DEV ? 'Prebuild (Dev)' : 'Prebuild',
  slug: 'prebuild-app',
  scheme: 'app',
  android: {
    package: 'com.example.prebuild',
    permissions: ['android.permission.RECORD_AUDIO', 'INTERNET'],
  },
  ios: {
    bundleIdentifier: 'com.example.prebuild',
  },
  extra: {
    sentryDsn: process.env.SENTRY_DSN,
  },
});
