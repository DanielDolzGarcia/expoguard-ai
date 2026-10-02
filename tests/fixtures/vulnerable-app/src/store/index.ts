import AsyncStorage from '@react-native-async-storage/async-storage';
import { persistReducer, persistStore } from 'redux-persist';
import { createStore } from 'redux';
import { rootReducer } from './reducers';

const persistConfig = {
  key: 'root',
  storage: AsyncStorage,
  whitelist: ['auth', 'cart'],
};

const persisted = persistReducer(persistConfig, rootReducer);
export const store = createStore(persisted);
export const persistor = persistStore(store);
