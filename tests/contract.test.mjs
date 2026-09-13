import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { startFixture } from './preview.mjs';

// The same sequence is exercised through the actual Setec provider in Go.
test('PROVIDER-1: UI fixture conforms to shared Setec lifecycle cases', async () => {
  const cases = JSON.parse(await readFile(new URL('./setec-contract.json', import.meta.url)));
  const fixture = await startFixture(0);
  try {
    fixture.secrets.clear();
    fixture.secrets.set('finance/hidden', {Name: 'finance/hidden', ActiveVersion: 1, Values: {1: 'eA=='}});
    fixture.secrets.set('finance/private/password', {Name: 'finance/private/password', ActiveVersion: 1, Values: {1: 'eA=='}});
    const {connection} = await (await fetch(fixture.url + '/ui-api/session')).json();
    for (const tc of cases) {
      const res = await fetch(fixture.url + '/ui-api/' + tc.op, {
        method: 'POST', headers: {'Content-Type': 'application/json', 'X-TailVault-Connection': connection},
        body: JSON.stringify(tc.body),
      });
      assert.equal(res.status, tc.status, tc.label);
      if (Object.hasOwn(tc, 'result')) assert.deepEqual(await res.json(), tc.result, tc.label);
      else await res.text();
    }
  } finally { await fixture.close(); }
});
