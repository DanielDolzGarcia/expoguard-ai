import axios from 'axios';
import { API_URL } from './config';

// axios SÍ se usa en el código; lodash está en package.json pero no se importa en ningún sitio.
export const api = axios.create({ baseURL: API_URL });
