package space.keshway.authentication.client;

import lombok.RequiredArgsConstructor;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.RequestCache;

@RequiredArgsConstructor
public abstract class AuthenticationSuccessProcessor implements AuthenticationSuccessHandler {
  protected final RequestCache requestCache;
  protected final SavedRequestAwareAuthenticationSuccessHandler targetUrlRequestHandler;
}
