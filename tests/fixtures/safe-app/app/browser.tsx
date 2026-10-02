import { useLocalSearchParams } from 'expo-router';
import * as Linking from 'expo-linking';
import { WebView } from 'react-native-webview';

const ALLOWED_HOSTS = ['help.safeshop.example'];

function isAllowedUrl(raw: string | undefined): raw is string {
  if (!raw) return false;
  try {
    const u = new URL(raw);
    return u.protocol === 'https:' && ALLOWED_HOSTS.includes(u.hostname);
  } catch {
    return false;
  }
}

export default function Browser() {
  const { url } = useLocalSearchParams<{ url: string }>();
  if (!isAllowedUrl(url)) {
    Linking.openURL('https://safeshop.example');
    return null;
  }
  return (
    <WebView
      source={{ uri: url }}
      originWhitelist={['https://help.safeshop.example']}
      javaScriptEnabled={false}
    />
  );
}
