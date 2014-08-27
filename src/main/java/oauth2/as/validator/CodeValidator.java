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

package oauth2.as.validator;

import oauth2.common.OAuth;
import oauth2.common.error.OAuthError;
import oauth2.common.exception.OAuthProblemException;
import oauth2.common.validators.AbstractValidator;
import play.mvc.Http.Request;



/**
 *
 *
 *
 */
public class CodeValidator extends AbstractValidator<Request> {

    public CodeValidator() {
        requiredParams.add(OAuth.OAUTH_RESPONSE_TYPE);
        requiredParams.add(OAuth.OAUTH_CLIENT_ID);
    }

    @Override
    public void validateMethod(Request request) throws OAuthProblemException {
        String method = request.method;
        if (!OAuth.HttpMethod.GET.equals(method) && !OAuth.HttpMethod.POST.equals(method)) {
            throw OAuthProblemException.error(OAuthError.CodeResponse.INVALID_REQUEST)
                .description("Method not correct.");
        }
    }

    @Override
    public void validateContentType(Request request) throws OAuthProblemException {
    }
}