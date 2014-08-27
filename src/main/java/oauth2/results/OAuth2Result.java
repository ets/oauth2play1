package oauth2.results;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import oauth2.common.message.OAuthResponse;
import play.exceptions.UnexpectedException;
import play.mvc.Http.Request;
import play.mvc.Http.Response;
import play.mvc.results.Result;



public class OAuth2Result extends Result {

    OAuthResponse oauthResponse;
    
    public OAuth2Result(OAuthResponse r){
        this.oauthResponse = r;
    }
    
    @Override
    public void apply(Request request, Response response) {
        response.status = oauthResponse.getResponseStatus();
        try {
            response.out.write(oauthResponse.getBody().getBytes("UTF8"));
        } catch (Exception e) {
            throw new UnexpectedException(e);
        }
    }

}
