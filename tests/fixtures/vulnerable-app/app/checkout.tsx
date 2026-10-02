import { useEffect, useRef } from 'react';
import * as Linking from 'expo-linking';
import { WebView } from 'react-native-webview';

export default function Checkout({ userName }: { userName: string }) {
  const ref = useRef<WebView>(null);

  useEffect(() => {
    const sub = Linking.addEventListener('url', (event) => {
      const { queryParams } = Linking.parse(event.url);
      const redirect = queryParams?.redirect as string;
      Linking.openURL(redirect);
    });
    return () => sub.remove();
  }, []);

  const onLoad = () => {
    ref.current?.injectJavaScript(`window.setUser('${userName}'); true;`);
  };

  return <WebView ref={ref} source={{ uri: 'https://pay.vulnshop.example' }} onLoad={onLoad} />;
}
