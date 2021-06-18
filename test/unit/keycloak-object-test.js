/*
 * Copyright 2016 Red Hat Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

'use strict';

const test = require('tape');
const Keycloak = require('../../');
const UUID = require('../../uuid');
const session = require('express-session');

let kc = null;

test('Should raise an error when no configuration is provided.', t => {
  t.throws(function () {
    var k = new Keycloak();
    t.notOk(k, 'Variable should be empty');
  }, Error, 'Adapter configuration must be provided.');
  t.end();
});

test('setup', t => {
  let kcConfig = {
    'realm': 'test-realm',
    'auth-server-url': 'http://localhost:8080/auth',
    'ssl-required': 'external',
    'resource': 'nodejs-connect',
    'public-client': true
  };

  let memoryStore = new session.MemoryStore();
  kc = new Keycloak({ store: memoryStore, scope: 'offline_support' }, kcConfig);
  t.end();
});

test('Should verify the realm name of the config object.', t => {
  t.equal(kc.config.realm, 'test-realm');
  t.end();
});

test('Should verify if login URL has the configured realm.', t => {
  t.equal(kc.loginUrl().indexOf(kc.config.realm) > 0, true);
  t.end();
});

test('Should verify if login URL has the custom scope value.', t => {
  t.equal(kc.loginUrl().indexOf(kc.config.scope) > 0, true);
  t.end();
});

test('Should verify if login URL has the default scope value.', t => {
  t.equal(kc.loginUrl().indexOf('openid') > 0, true);
  t.end();
});

test('Should verify if logout URL has the configured realm.', t => {
  t.equal(kc.logoutUrl().indexOf(kc.config.realm) > 0, true);
  t.end();
});

test('Should generate a correct UUID.', t => {
  const rgx = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
  t.equal(rgx.test(UUID()), true);
  t.end();
});

test('Should produce correct account url.', t => {
  t.equal(kc.accountUrl(), 'http://localhost:8080/auth/realms/test-realm/account');
  t.end();
});

test('Should update the config.', t => {
  const mockConfig = {
    'realm': 'test-realm',
    'auth-server-url': 'http://localhost:8080/auth',
    'ssl-required': 'external',
    'resource': 'nodejs-connect',
    'public-client': true
  };
  kc.setConfig(mockConfig);
  t.equal(kc.getConfig(), mockConfig);
  t.end();
});
