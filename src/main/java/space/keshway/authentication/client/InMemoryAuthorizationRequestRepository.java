package space.keshway.authentication.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

class InMemoryAuthorizationRequestRepository
    implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

  private final Map<String, OAuth2AuthorizationRequest> authorizationRequestMap = new HashMap<>();

  @Override
  public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
    String state = request.getParameter(OAuth2ParameterNames.STATE);
    return authorizationRequestMap.get(state);
  }

  @Override
  public void saveAuthorizationRequest(
      OAuth2AuthorizationRequest authorizationRequest,
      HttpServletRequest request,
      HttpServletResponse response) {
    if (authorizationRequest == null) {
      String state = request.getParameter(OAuth2ParameterNames.STATE);
      if (state == null) return;
      authorizationRequestMap.remove(state);
      return;
    }
    authorizationRequestMap.put(authorizationRequest.getState(), authorizationRequest);
  }

  @Override
  public OAuth2AuthorizationRequest removeAuthorizationRequest(
      HttpServletRequest request, HttpServletResponse response) {
    String state = request.getParameter(OAuth2ParameterNames.STATE);
    return authorizationRequestMap.remove(state);
  }
}
