package space.keshway.authentication.client;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Instant;
import java.util.Iterator;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.server.ResponseStatusException;

@RequiredArgsConstructor
public class JwtSecurityContextRepository implements SecurityContextRepository {

  private static final String CLAIM_ROLES = "roles";

  private final InMemoryClientRegistrationRepository repository;
  private final JwtDecoder jwtDecoder;
  private final OAuth2AuthorizedClientService service;

  @Override
  public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
    SecurityContext context = loadContext(requestResponseHolder.getRequest()).get();
    if (context == null) {
      context = SecurityContextHolder.createEmptyContext();
    }
    return context;
  }

  @Override
  public void saveContext(
      SecurityContext context, HttpServletRequest request, HttpServletResponse response) {}

  @Override
  public boolean containsContext(HttpServletRequest request) {
    return loadContext(request).get() != null;
  }

  private Supplier<SecurityContext> loadContext(HttpServletRequest request) {
    return new SecurityContextSupplier(request);
  }

  private final class SecurityContextSupplier implements DeferredSecurityContext {

    private final HttpServletRequest request;

    private SecurityContextSupplier(HttpServletRequest request) {
      this.request = request;
    }

    @Override
    public SecurityContext get() {
      Optional<String> token = getToken();
      if (token.isEmpty()) return null;
      try {
        Jwt decodedToken = jwtDecoder.decode(token.get());
        ClientRegistration currentClientRegistration = getClientRegistration();
        Optional<OAuth2AuthorizedClient> oAuth2AuthorizedClient =
            getAuthorizedClient(currentClientRegistration, decodedToken);
        if (oAuth2AuthorizedClient.isEmpty()
            || isClientTokenExpired(oAuth2AuthorizedClient.get())) {
          return null;
        }
        Set<SimpleGrantedAuthority> rolesFromToken = getRolesFromToken(decodedToken);
        return new SecurityContextImpl(
            createOAuth2AuthenticationToken(
                decodedToken, currentClientRegistration, rolesFromToken));
      } catch (JwtException e) {
        throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, e.getMessage());
      }
    }

    private Optional<String> getToken() {
      Optional<String> authTokenHeader =
          Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION));
      Optional<Cookie> authorizationCookie =
          CookieHelper.getCookie(request, CookieType.AUTHORIZATION.getName());
      return authTokenHeader
          .map(SecurityContextSupplier::getBearerTokenValue)
          .or(() -> authorizationCookie.map(Cookie::getValue));
    }

    private ClientRegistration getClientRegistration() {
      Iterator<ClientRegistration> clientRegistrationIterator = repository.iterator();
      if (!clientRegistrationIterator.hasNext())
        throw new ResponseStatusException(
            HttpStatus.INTERNAL_SERVER_ERROR, "Could not find client registration!");
      return clientRegistrationIterator.next();
    }

    private Optional<OAuth2AuthorizedClient> getAuthorizedClient(
        ClientRegistration currentClientRegistration, Jwt decodedToken) {
      return Optional.ofNullable(
          service.loadAuthorizedClient(
              currentClientRegistration.getRegistrationId(),
              decodedToken.getClaimAsString(IdTokenClaimNames.SUB)));
    }

    private static boolean isClientTokenExpired(OAuth2AuthorizedClient oAuth2AuthorizedClient) {
      return Instant.now()
          .isAfter(Objects.requireNonNull(oAuth2AuthorizedClient.getAccessToken().getExpiresAt()));
    }

    private static Set<SimpleGrantedAuthority> getRolesFromToken(Jwt decodedToken) {
      return decodedToken.getClaimAsStringList(CLAIM_ROLES).stream()
          .map(SimpleGrantedAuthority::new)
          .collect(Collectors.toSet());
    }

    private static OAuth2AuthenticationToken createOAuth2AuthenticationToken(
        Jwt decodedToken,
        ClientRegistration currentClientRegistration,
        Set<SimpleGrantedAuthority> rolesFromToken) {
      return new OAuth2AuthenticationToken(
          new DefaultOidcUser(
              rolesFromToken,
              new OidcIdToken(
                  decodedToken.getTokenValue(),
                  decodedToken.getIssuedAt(),
                  decodedToken.getExpiresAt(),
                  decodedToken.getClaims())),
          rolesFromToken,
          currentClientRegistration.getRegistrationId());
    }

    @Override
    public boolean isGenerated() {
      return false;
    }

    private static String getBearerTokenValue(String header) {
      try {
        return header.split(OAuth2AccessToken.TokenType.BEARER.getValue() + " ")[1];
      } catch (ArrayIndexOutOfBoundsException e) {
        throw new ResponseStatusException(
            HttpStatus.BAD_REQUEST, "Provided wrong authorization header.");
      }
    }
  }
}
