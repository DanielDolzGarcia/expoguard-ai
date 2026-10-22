import type { Detector } from '../types.js';
import { secretsDetector } from './secrets.js';
import { storageDetector } from './storage.js';
import { dependenciesDetector } from './dependencies.js';
import { webviewDetector } from './webview.js';
import { nativeDetector } from './native.js';

export const DETECTORS: Detector[] = [secretsDetector, storageDetector, dependenciesDetector, webviewDetector, nativeDetector];
