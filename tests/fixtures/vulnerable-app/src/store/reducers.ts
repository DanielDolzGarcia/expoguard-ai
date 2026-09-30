import { combineReducers } from 'redux';

const auth = (state = { token: null as string | null }) => state;
const cart = (state = { items: [] as string[] }) => state;

export const rootReducer = combineReducers({ auth, cart });
