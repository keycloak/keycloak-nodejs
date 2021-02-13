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

var Token = require('./auth-utils/token');
var Signature = require('./auth-utils/signature');

function Admin (keycloak, url) {
  this._keycloak = keycloak;
  if (url[ url.length - 1 ] !== '/') {
    url += '/;';
  }
  this._url = url + 'k_logout';
}

Admin.prototype.getFunction = function () {
  return this._adminRequest.bind(this);
};

function adminLogout (request, response, keycloak) {
  let data = '';

  request.on('data', d => {
    data += d.toString();
  });

  request.on('end', function () {
    let token = new Token(data);
    let signature;
    try {
      signature = new Signature(keycloak.config);
      signature.verify(token).then(token => {
        if (token.content.action === 'LOGOUT') {
          let sessionIDs = token.content.adapterSessionIds;
          if (!sessionIDs) {
            keycloak.grantManager.notBefore = token.content.notBefore;
            response.end('ok');
            return;
          }
          if (sessionIDs && sessionIDs.length > 0) {
            let seen = 0;
            sessionIDs.forEach(id => {
              keycloak.unstoreGrant(id);
              ++seen;
              if (seen === sessionIDs.length) {
                response.end('ok');
              }
            });
          } else {
            response.end('ok');
          }
        } else {
          response.statusCode = 400;
          response.end();
        }
      }).catch((err) => {
        response.statusCode = 401;
        response.end(err.message);
      });
    } catch (err) {
      response.statusCode = 400;
      response.end(err.message);
    }
  });
}

function adminNotBefore (request, response, keycloak) {
  let data = '';
  request.on('data', d => {
    data += d.toString();
  });

  request.on('end', function () {
    let token = new Token(data);
    let signature;
    try {
      signature = new Signature(keycloak.config);
      signature.verify(token).then(token => {
        if (token.content.action === 'PUSH_NOT_BEFORE') {
          keycloak.grantManager.notBefore = token.content.notBefore;
          response.end('ok');
        }
      }).catch((err) => {
        response.statusCode = 401;
        response.end(err.message);
      });
    } catch (err) {
      response.statusCode = 400;
      response.end(err.message);
    }
  });
}

module.exports = function (keycloak, adminUrl) {
  let url = adminUrl;
  if (url[ url.length - 1 ] !== '/') {
    url = url + '/';
  }
  let urlLogout = url + 'k_logout';
  let urlNotBefore = url + 'k_push_not_before';

  return function adminRequest (request, response, next) {
    switch (request.url) {
      case urlLogout:
        adminLogout(request, response, keycloak);
        break;
      case urlNotBefore:
        adminNotBefore(request, response, keycloak);
        break;
      default:
        return next();
    }
  };
};
