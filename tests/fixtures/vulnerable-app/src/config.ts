// Configuración de la app (fixture vulnerable: TODAS las claves son falsas)
export const API_URL = 'https://api.vulnshop.example';

export const AWS_ACCESS_KEY_ID = 'AKIAIOSFODNN7EXAMPLE';

export const FIREBASE_API_KEY = 'AIzaSyFAKE_expoguard_0000000000000000';

const apiSecret = 'Zx9fQ2LmP8vR4tW7yB1nK6hJ3sD5gA0c';

export const SIGNING_KEY = `-----BEGIN RSA PRIVATE KEY-----
MIIEFAKEexpoguardNOTAREALKEY
-----END RSA PRIVATE KEY-----`;

export function authHeader() {
  return { 'X-Api-Secret': apiSecret };
}
