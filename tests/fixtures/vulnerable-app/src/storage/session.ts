import AsyncStorage from '@react-native-async-storage/async-storage';

const USER_KEY = '@user_credentials';

export async function saveSession(token: string) {
  await AsyncStorage.setItem('accessToken', token);
  console.log('login ok, token:', token);
}

export async function saveUser(user: { email: string; password: string }) {
  await AsyncStorage.setItem(USER_KEY, JSON.stringify(user));
}

export async function saveTheme(theme: 'light' | 'dark') {
  await AsyncStorage.setItem('theme', theme);
}
