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

const URL = require('url');

module.exports = function (keycloak, logoutUrl) {
  return function logout (request, response, next) {
    let parsedRequest = URL.parse(request.url, true);
    if (parsedRequest.pathname !== logoutUrl) {
      return next();
    }

    if (request.kauth.grant) {
      keycloak.deauthenticated(request);
      request.kauth.grant.unstore(request, response);
      delete request.kauth.grant;
    }

    let queryParams = parsedRequest.query;
    let redirectUrl = queryParams && queryParams.redirect_url;
    if (!redirectUrl) {
      let host = request.hostname;
      let headerHost = request.headers.host.split(':');
      let port = headerHost[1] || '';
      redirectUrl = request.protocol + '://' + host + (port === '' ? '' : ':' + port) + '/';
    }
    let keycloakLogoutUrl = keycloak.logoutUrl(redirectUrl);

    response.writeHead(302, { Location: keycloakLogoutUrl }).end()
  };
};
