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

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.cxf.jaxrs.ext.RequestHandler;
import org.apache.cxf.jaxrs.model.ClassResourceInfo;
import org.apache.cxf.message.Message;
import org.buddycode.jaxrs.samplejaxrs.bean.StandardResponse;

import javax.ws.rs.core.Response;
import java.util.ArrayList;
import java.util.List;
import java.util.TreeMap;

/**
 * This class will register authentication handlers for the application
 */
public class AuthenticationFilter implements RequestHandler {

    private static Log log = LogFactory.getLog(AuthenticationFilter.class);
    private final ArrayList<AuthenticationHandler> authenticationHandlers = new ArrayList<AuthenticationHandler>();

    public AuthenticationFilter() {
        try {
            this.loadAuthenticationHandlers();
        } catch (Exception e) {
            log.error("Error occurred while initializing AuthenticationFilter.", e);
        }
    }

    @Override
    public Response handleRequest(Message message, ClassResourceInfo classResourceInfo) {
        boolean authenticated = false;
        for (AuthenticationHandler handler : authenticationHandlers) {  // iterate through all the registered handlers
            TreeMap protocolHeaders = (TreeMap) message.get(Message.PROTOCOL_HEADERS);
            if (handler.canHandle(protocolHeaders)) {                   // if the handler can handle
                authenticated = handler.isAuthenticated(protocolHeaders);
            }
        }
        if (authenticated) {
            return null;
        } else {
            return handleError();
        }
    }

    private Response handleError() {
        log.error("Failed authentication");
        return Response.status(HttpStatus.SC_UNAUTHORIZED).
                entity(new StandardResponse("failed authentication")).build();
    }

    /**
     * Load authentication handlers and register them.
     *
     * @throws InstantiationException
     * @throws IllegalAccessException
     * @throws ClassNotFoundException
     * @throws ConfigurationException
     */
    private void loadAuthenticationHandlers()
            throws InstantiationException, IllegalAccessException, ClassNotFoundException, ConfigurationException {

        XMLConfiguration config = new XMLConfiguration("sample_jaxrs.xml");
        List<String> fields = config.getList("authenticationHandlers.handler");
        for (String authenticationHandlerClassName : fields) {
            AuthenticationHandler authenticationHandler = (AuthenticationHandler) Class.forName
                    (authenticationHandlerClassName)
                    .newInstance();
            authenticationHandlers.add(authenticationHandler);
        }
    }
}
