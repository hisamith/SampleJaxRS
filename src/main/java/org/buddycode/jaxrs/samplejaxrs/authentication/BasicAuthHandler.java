/*
 * Copyright (c) 2015, Samith Dassanayake. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.buddycode.jaxrs.samplejaxrs.authentication;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Map;

/**
 * Basic Athunteication Handler
 */
public class BasicAuthHandler implements AuthenticationHandler {
    private static final Log log = LogFactory.getLog(BasicAuthHandler.class);
    public static final String BASIC_AUTH_HEADER = "Basic";
    public static final String AUTHORIZATION_HEADER = "Authorization";
    public static final String AUTH_HEADER_SPLITTER = " ";
    public static final String DECODED_AUTH_HEADER_SPLITTER = ":";

    @Override
    public boolean canHandle(Map headers) {
        //get the value for Authorization Header
        ArrayList authzHeaders = (ArrayList) headers.get(AUTHORIZATION_HEADER);

        if (authzHeaders != null) {
            // get the authorization header value, if provided
            String authzHeader = (String) authzHeaders.get(0);
            if (authzHeader != null && authzHeader.contains(BASIC_AUTH_HEADER)) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean isAuthenticated(Map headers) {

        //get the value for Authorization Header
        ArrayList authzHeaders = (ArrayList) headers.get(AUTHORIZATION_HEADER);
        if (authzHeaders != null) {
            //get the authorization header value, if provided
            String authzHeader = (String) authzHeaders.get(0);

            //decode it and extract username and password
            byte[] decodedAuthHeader = Base64.decode(authzHeader.split(AUTH_HEADER_SPLITTER)[1]);
            String authHeader = new String(decodedAuthHeader);
            String userName = authHeader.split(DECODED_AUTH_HEADER_SPLITTER)[0];
            String password = authHeader.split(DECODED_AUTH_HEADER_SPLITTER)[1];
            if (userName != null && password != null) {
                String tenantDomain = MultitenantUtils.getTenantDomain(userName);
                String tenantLessUserName = MultitenantUtils.getTenantAwareUsername(userName);

                try {
                    // get super tenant context and get realm service which is an osgi service
                    RealmService realmService = (RealmService) PrivilegedCarbonContext
                            .getThreadLocalCarbonContext().getOSGiService(RealmService.class);
                    if (realmService != null) {
                        int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
                        if (tenantId == -1) {
                            log.error("Invalid tenant domain " + tenantDomain);
                            return false;
                        }
                        //get tenant's user realm
                        UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
                        boolean authenticated = userRealm.getUserStoreManager().
                                authenticate(tenantLessUserName, password);
                        if (authenticated) {
                            //authentication success. set the username for authorization header
                            //and proceed the REST call
                            authzHeaders.set(0, userName);
                            return true;
                        } else {
                            log.error("Authentication failed for the user: " +
                                      getFullUserName(tenantDomain, tenantLessUserName));
                            return false;
                        }
                    } else {
                        log.error("Error in getting Realm Service for user: " + userName + ".Authentication failed " +
                                  "for the user: " + getFullUserName(tenantDomain, tenantLessUserName));
                        return false;
                    }
                } catch (UserStoreException e) {
                    log.error("Internal server error while authenticating the user.");
                    return false;
                }
            } else {
                log.error("Authentication required for this resource. Username or password not provided.");
                return false;
            }
        } else {
            log.error("Authentication required for this resource. Authorization header not present in the request.");
            return false;
        }

    }

    private String getFullUserName(String tenantDomain, String tenantLessUserName) {
        return tenantLessUserName
               + UserCoreConstants.TENANT_DOMAIN_COMBINER + tenantDomain;
    }
}
