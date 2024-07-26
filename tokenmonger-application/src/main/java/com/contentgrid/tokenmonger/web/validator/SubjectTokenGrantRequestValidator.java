package com.contentgrid.tokenmonger.web.validator;

import com.contentgrid.tokenmonger.oauth2.grants.TokenExchangeGrantRequest;
import com.contentgrid.tokenmonger.oauth2.token.decoder.TokenDecoder;
import com.contentgrid.tokenmonger.web.validator.SubjectTokenGrantRequestValidator.SubjectTokenInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.jwt.Jwt;

@RequiredArgsConstructor
public class SubjectTokenGrantRequestValidator<C extends SubjectTokenInfo> implements GrantRequestValidator<TokenExchangeGrantRequest, C> {
    private final TokenDecoder<Jwt> tokenDecoder;

    @Override
    public String getDescription() {
        return "A subject token is required";
    }

    @Override
    public void validate(TokenExchangeGrantRequest grantRequest, C context) {
        context.setSubjectToken(tokenDecoder.decode(grantRequest.getSubjectToken()));
    }

    public interface SubjectTokenInfo {
        void setSubjectToken(Jwt subjectToken);
        Jwt getSubjectToken();
    }

}
