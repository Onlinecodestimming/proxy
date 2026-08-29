// Loads the JSON data files, with optional overrides (tests, embedding).

import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'config');

const read = (f) => JSON.parse(readFileSync(path.join(dir, f), 'utf8'));

export function loadConfig(overrides = {}) {
  return {
    trackers: overrides.trackers ?? read('trackers.json'),
    params: overrides.params ?? read('tracking-params.json'),
    cookies: overrides.cookies ?? read('tracking-cookies.json'),
  };
}
