package space.keshway.authentication.client;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@RequiredArgsConstructor
class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
  private final AuthenticationSuccessProcessor successProcessor;

  @Override
  public void onAuthenticationSuccess(
      HttpServletRequest request, HttpServletResponse response, Authentication authentication)
      throws IOException, ServletException {
    if (authentication instanceof OAuth2AuthenticationToken token) {
      OidcUser accessToken = (OidcUser) token.getPrincipal();
      CookieHelper.addCookie(
          request,
          response,
          CookieType.AUTHORIZATION.getName(),
          accessToken.getIdToken().getTokenValue(),
          accessToken.getExpiresAt());
      successProcessor.onAuthenticationSuccess(request, response, authentication);
    }
  }
}
