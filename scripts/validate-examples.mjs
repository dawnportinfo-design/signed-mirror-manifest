import fs from 'node:fs';
import path from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';
import addFormats from 'ajv-formats';

const root = process.cwd();
const readJson = (filePath) => JSON.parse(fs.readFileSync(path.join(root, filePath), 'utf8'));
const ajv = new Ajv2020({ allErrors: true });
addFormats(ajv);
const validate = ajv.compile(readJson('schemas/mirror-manifest.schema.json'));
const vector = readJson('test-vectors/manifest-v1-ed25519.json');
const checks = [
  {
    name: 'unsigned example manifest',
    data: readJson('examples/unsigned-manifest.json'),
  },
  {
    name: 'Ed25519 test vector signed manifest',
    data: vector.signed_manifest,
  },
];

let failed = false;

for (const check of checks) {
  if (!validate(check.data)) {
    failed = true;
    console.error(`Invalid ${check.name}`);
    console.error(validate.errors);
  }
}

if (failed) {
  process.exit(1);
}

console.log('Example manifests match JSON Schema.');
