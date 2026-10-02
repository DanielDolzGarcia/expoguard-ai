import { useLocalSearchParams } from 'expo-router';
import { WebView } from 'react-native-webview';

export default function Browser() {
  const { url } = useLocalSearchParams<{ url: string }>();
  return (
    <WebView
      source={{ uri: url }}
      originWhitelist={['*']}
      allowFileAccess
      allowUniversalAccessFromFileURLs={true}
      mixedContentMode="always"
    />
  );
}
