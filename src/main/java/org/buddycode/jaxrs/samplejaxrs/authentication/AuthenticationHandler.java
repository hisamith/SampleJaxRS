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

import java.util.Map;

/**
 * Authentication Handler interface
 */
public interface AuthenticationHandler {
    /**
     * Returns whether the authenticator can handle the request
     *
     * @param httpHeaders
     * @return Return true if the request can be handled, false otherwise
     */
    public boolean canHandle(Map httpHeaders);

    /**
     * Process the request and  return the result
     *
     * @param httpHeaders
     * @return true if authentication successful, false otherwise
     */
    public boolean isAuthenticated(Map httpHeaders);
}
