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

package oauth2.common.validators;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import oauth2.common.OAuth;
import oauth2.common.exception.OAuthProblemException;
import oauth2.common.utils.OAuthUtils;
import play.mvc.Http.Header;
import play.mvc.Http.Request;

/**
 *
 *
 *
 */
//todo add client secret in header, sect 2.1
public abstract class AbstractValidator<T extends Request> implements OAuthValidator<T> {

    protected List<String> requiredParams = new ArrayList<String>();
    protected Map<String, String[]> optionalParams = new HashMap<String, String[]>();
    protected List<String> notAllowedParams = new ArrayList<String>();


    @Override
    public void validateMethod(T Request) throws OAuthProblemException {
        if (!Request.method.equals(OAuth.HttpMethod.POST)) {
            throw OAuthUtils.handleOAuthProblemException("Method not set to POST.");
        }
    }

    @Override
    public void validateContentType(T request) throws OAuthProblemException {


    	Header o = request.headers.get(OAuth.HeaderType.CONTENT_TYPE);
        String contentType = o == null ?null:o.value();

        final String expectedContentType = OAuth.ContentType.URL_ENCODED;
        if (!OAuthUtils.hasContentType(contentType, expectedContentType)) {
            throw OAuthUtils.handleBadContentTypeException(expectedContentType);
        }
    }

    @Override
    public void validateRequiredParameters(T request) throws OAuthProblemException {
        Set<String> missingParameters = new HashSet<String>();
        for (String requiredParam : requiredParams) {
        	String val = request.params.get(requiredParam);        	            
            if (OAuthUtils.isEmpty(val)) {
                missingParameters.add(requiredParam);
            }
        }
        if (!missingParameters.isEmpty()) {
            throw OAuthUtils.handleMissingParameters(missingParameters);
        }
    }

    @Override
    public void validateOptionalParameters(T request) throws OAuthProblemException {
        Set<String> missingParameters = new HashSet<String>();

        for (Map.Entry<String, String[]> requiredParam : optionalParams.entrySet()) {
            String paramName = requiredParam.getKey();
            String val = request.params.get(paramName);
            if (!OAuthUtils.isEmpty(val)) {
                String[] dependentParams = requiredParam.getValue();
                if (!OAuthUtils.hasEmptyValues(dependentParams)) {
                    for (String dependentParam : dependentParams) {
                        val = request.params.get(dependentParam);
                        if (OAuthUtils.isEmpty(val)) {
                            missingParameters.add(dependentParam);
                        }
                    }
                }
            }
        }

        if (!missingParameters.isEmpty()) {
            throw OAuthUtils.handleMissingParameters(missingParameters);
        }
    }

    @Override
    public void validateNotAllowedParameters(T request) throws OAuthProblemException {
        List<String> notAllowedParameters = new ArrayList<String>();
        for (String invalidParamKey : notAllowedParams) {
        	String o = request.params.get(invalidParamKey);
            if (!OAuthUtils.isEmpty(o)) {
                notAllowedParameters.add(invalidParamKey);
            }
        }
        if (!notAllowedParameters.isEmpty()) {
            throw OAuthUtils.handleNotAllowedParametersOAuthException(notAllowedParameters);
        }
    }

    @Override
    public void performAllValidations(T Request) throws OAuthProblemException {
        this.validateContentType(Request);
        this.validateMethod(Request);
        this.validateRequiredParameters(Request);
        this.validateOptionalParameters(Request);
        this.validateNotAllowedParameters(Request);
    }
}
