/**
 *       Copyright 2010 Newcastle University
 *
 *          http://research.ncl.ac.uk/smart/
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package oauth2.as.request;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import oauth2.common.OAuth;
import oauth2.common.exception.OAuthProblemException;
import oauth2.common.exception.OAuthSystemException;
import oauth2.common.utils.OAuthUtils;
import oauth2.common.validators.OAuthValidator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import play.mvc.Http;
import play.mvc.Http.Request;

/**
 *
 *
 *
 */
public abstract class OAuthRequest {

    private Logger log = LoggerFactory.getLogger(OAuthRequest.class);

    protected Request request;
    protected OAuthValidator<Request> validator;
    protected Map<String, Class<? extends OAuthValidator<Request>>> validators =
        new HashMap<String, Class<? extends OAuthValidator<Request>>>();

    public OAuthRequest(Request request) throws OAuthSystemException, OAuthProblemException {
        this.request = request;
        validate();
    }

    public OAuthRequest() {
    }

    protected void validate() throws OAuthSystemException, OAuthProblemException {
        try {
            validator = initValidator();
            validator.validateMethod(request);
            validator.validateContentType(request);
            validator.validateRequiredParameters(request);
        } catch (OAuthProblemException e) {
            try {
            	
                String redirectUri = request.params.get(OAuth.OAUTH_REDIRECT_URI);                                
                if (!OAuthUtils.isEmpty(redirectUri)) {
                    e.setRedirectUri(redirectUri);
                }
            } catch (Exception ex) {
                if (log.isDebugEnabled()) {
                    log.debug("Cannot read redirect_url from the request: {}", new String[] {ex.getMessage()});
                }
            }

            throw e;
        }

    }

    protected abstract OAuthValidator<Request> initValidator() throws OAuthProblemException,
        OAuthSystemException;

    public String getParam(String name) {
		return request.params.get(name);
    }

    public String getClientId() {
        return getParam(OAuth.OAUTH_CLIENT_ID);
    }

    public String getRedirectURI() {
        return getParam(OAuth.OAUTH_REDIRECT_URI);
    }

    public String getClientSecret() {
        return getParam(OAuth.OAUTH_CLIENT_SECRET);
    }

    public Set<String> getScopes() {
        String scopes = getParam(OAuth.OAUTH_SCOPE);
        return OAuthUtils.decodeScopes(scopes);
    }

}
