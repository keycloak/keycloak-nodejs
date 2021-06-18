/*!
 * Copyright 2014 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

'use strict';

const path = require('path');
const fs = require('fs');

/**
 * Construct a configuration object.
 *
 * A configuration object may be constructed with either
 * a path to a `keycloak.json` file (which defaults to
 * `$PWD/keycloak.json` if not present, or with a configuration
 * object akin to what parsing `keycloak.json` provides.
 *
 * @param {String|Object} config Configuration path or details.
 *
 * @constructor
 */
function Config (config) {
  if (!config) {
    config = path.join(process.cwd(), 'keycloak.json');
  }

  if (typeof config === 'string') {
    this.loadConfiguration(config);
  } else {
    this.configure(config);
  }
}

/**
 * Load configuration from a path.
 *
 * @param {String} configPath Path to a `keycloak.json` configuration.
 */
Config.prototype.loadConfiguration = function loadConfiguration (configPath) {
  const json = fs.readFileSync(configPath);
  const config = JSON.parse(json.toString());
  this.configure(config);
};

/**
 * Configure this `Config` object.
 *
 * This will set the internal configuration details.  The details
 * may come from a `keycloak.json` formatted object (with names such
 * as `auth-server-url`) or from an existing `Config` object (using
 * names such as `authServerUrl`).
 *
 * @param {Object} config The configuration to instill.
 */
Config.prototype.configure = function configure (config) {
  /**
   * Tries to resolve environment variables in the given value in case it is of type "string", else the given value is returned.
   * Environment variable references look like: '${env.MY_ENVIRONMENT_VARIABLE}', optionally one can configure a fallback
   * if the referenced env variable is not present. E.g. '${env.NOT_SET:http://localhost:8080}' yields 'http://localhost:8080'.
   *
   * @param value
   * @returns {*}
   */
  function resolveValue (value) {
    if (typeof value !== 'string') {
      return value;
    }

    // "${env.MY_ENVIRONMENT_VARIABLE:http://localhost:8080}".replace(/\$\{env\.([^:]*):?(.*)?\}/,"$1--split--$2").split("--split--")
    let regex = /\$\{env\.([^:]*):?(.*)?\}/;

    // is this an environment variable reference with potential fallback?
    if (!regex.test(value)) {
      return value;
    }

    let tokens = value.replace(regex, '$1--split--$2').split('--split--');
    let envVar = tokens[0];
    let envVal = process.env[envVar];
    let fallbackVal = tokens[1];

    return envVal || fallbackVal;
  }

  /**
   * Realm ID
   * @type {String}
   */
  this.realm = resolveValue(config.realm || config.realm);

  /**
   * Client/Application ID
   * @type {String}
   */
  this.clientId = resolveValue(config.resource || config['client-id'] || config.clientId);

  /**
   * Client/Application secret
   * @type {String}
   */
  this.secret = resolveValue((config.credentials || {}).secret || config.secret);

  /**
   * If this is a public application or confidential.
   * @type {String}
   */
  this.public = resolveValue(config['public-client'] || config.public || false);

  /**
   * Enable/Disable the use of X-Custom headers
   * @type {String}
   */
  this.useCustomHeaders = resolveValue(config.useCustomHeaders || true);

  /**
   * Authentication server URL
   * @type {String}
   */
  this.authServerUrl = (resolveValue(config['auth-server-url'] || config['server-url'] || config.serverUrl || config.authServerUrl) || '').replace(/\/*$/gi, '');

  /**
   * Root realm URL.
   * @type {String}
   */
  this.realmUrl = this.authServerUrl + '/realms/' + this.realm;

  /**
   * Root realm admin URL.
   * @type {String} */
  this.realmAdminUrl = this.authServerUrl + '/admin/realms/' + this.realm;

  /**
   * How many minutes before retrying getting the keys.
   * @type {Integer}
   */
  this.minTimeBetweenJwksRequests = config['min-time-between-jwks-requests'] || config.minTimeBetweenJwksRequests || 10;

  /**
   * If this is a Bearer Only application.
   * @type {Boolean}
   */
  this.bearerOnly = resolveValue(config['bearer-only'] || config.bearerOnly || false);

  /**
    * Formatted public-key.
    * @type {String}
    */
  const plainKey = resolveValue(config['realm-public-key'] || config.realmPublicKey);

  if (plainKey) {
    this.publicKey = '-----BEGIN PUBLIC KEY-----\n';
    for (let i = 0; i < plainKey.length; i = i + 64) {
      this.publicKey += plainKey.substring(i, i + 64);
      this.publicKey += '\n';
    }
    this.publicKey += '-----END PUBLIC KEY-----';
  }

  /**
   * Verify token audience
   * @type {Boolean}
   */
  this.verifyTokenAudience = resolveValue(config['verify-token-audience'] || config.verifyTokenAudience || false);
};

module.exports = Config;
