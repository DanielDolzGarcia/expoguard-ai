// Solo valores públicos; los secretos viven en el servidor.
export const API_URL = process.env.EXPO_PUBLIC_API_URL ?? 'https://api.safeshop.example';

// Nombre de la clave, no su valor.
export const TOKEN_STORAGE_KEY = 'accessToken';

// Valor de ejemplo en documentación, no es una clave.
export const API_KEY_PLACEHOLDER = 'your-api-key-here-please';
