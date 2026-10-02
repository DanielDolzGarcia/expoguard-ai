import * as SecureStore from 'expo-secure-store';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { TOKEN_STORAGE_KEY } from '../config';

export async function saveSession(token: string) {
  await SecureStore.setItemAsync(TOKEN_STORAGE_KEY, token);
  console.log('login ok');
}

export async function saveTheme(theme: 'light' | 'dark') {
  await AsyncStorage.setItem('theme', theme);
}
