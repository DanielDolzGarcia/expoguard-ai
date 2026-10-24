// Fixture yarn-app: mismo cliente HTTP que vulnerable-app, pero el proyecto usa yarn.
import axios from 'axios';

export const api = axios.create({ baseURL: 'https://api.yarnshop.example', timeout: 10_000 });
