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

package oauth2.rs.extractor;

import oauth2.common.OAuth;
import oauth2.common.utils.OAuthUtils;
import play.mvc.Http.Request;


/**
 *
 *
 *
 */
public class BearerHeaderTokenExtractor implements TokenExtractor {


    @Override
    public String getAccessToken(Request request) {
        String authzHeader = request.headers.containsKey(OAuth.HeaderType.AUTHORIZATION) ? request.headers.get(OAuth.HeaderType.AUTHORIZATION).value() : null;
        return OAuthUtils.getAuthHeaderField(authzHeader);
    }

    @Override
    public String getAccessToken(Request request, String tokenName) {
        String authzHeader = request.headers.containsKey(OAuth.HeaderType.AUTHORIZATION) ? request.headers.get(OAuth.HeaderType.AUTHORIZATION).value() : null;
        return OAuthUtils.getAuthHeaderField(authzHeader);
    }


}
