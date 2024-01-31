package space.keshway.authentication.client;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.RequestCacheConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.DelegatingSecurityContextRepository;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

@EnableWebSecurity
@Configuration
public class JwtSecurityConfig {

  @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}")
  private String issuerUri;

  @SuppressWarnings("unused")
  protected HttpSecurity configure(
      HttpSecurity http,
      OAuth2AuthorizedClientService clientService,
      ClientRegistrationRepository clientRegistrationRepository,
      JwtSecurityContextRepository jwtSecurityContextRepository,
      AuthenticationSuccessProcessor successProcessor,
      SavedRequestAwareAuthenticationSuccessHandler delegate,
      RequestCache requestCache)
      throws Exception {
    delegate.setRequestCache(requestCache);
    http.securityContext(
            sc ->
                sc.securityContextRepository(
                    new DelegatingSecurityContextRepository(
                        new RequestAttributeSecurityContextRepository(),
                        jwtSecurityContextRepository)))
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .requestCache(c -> c.requestCache(requestCache))
        .oauth2Login(
            oauth2 ->
                oauth2
                    .authorizationEndpoint(
                        e ->
                            e.authorizationRequestRepository(
                                new InMemoryAuthorizationRequestRepository()))
                    .authorizedClientRepository(
                        authenticatedPrincipalOAuth2AuthorizedClientRepository(clientService))
                    .successHandler(authenticationSuccessHandler(successProcessor)))
        .oauth2Client(Customizer.withDefaults())
        .logout(
            logout ->
                logout
                    .deleteCookies(CookieType.AUTHORIZATION.name())
                    .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository)));
    return http;
  }

  protected AuthenticatedPrincipalOAuth2AuthorizedClientRepository
      authenticatedPrincipalOAuth2AuthorizedClientRepository(
          OAuth2AuthorizedClientService clientService) {
    return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(clientService);
  }

  protected AuthenticationSuccessHandler authenticationSuccessHandler(
      AuthenticationSuccessProcessor successProcessor) {
    return new JwtAuthenticationSuccessHandler(successProcessor);
  }

  protected LogoutSuccessHandler oidcLogoutSuccessHandler(
      ClientRegistrationRepository clientRegistrationRepository) {
    OidcClientInitiatedLogoutSuccessHandler oidcLogoutSuccessHandler =
        new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
    oidcLogoutSuccessHandler.setPostLogoutRedirectUri("{baseUrl}/");
    return oidcLogoutSuccessHandler;
  }

  @Bean
  protected OAuth2AuthorizedClientService oAuth2AuthorizedClient(
      ClientRegistrationRepository clientRegistrationRepository) {
    return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
  }

  @Bean
  protected JwtDecoder jwtDecoder() {
    return JwtDecoders.fromIssuerLocation(issuerUri);
  }

  @Bean
  protected JwtSecurityContextRepository securityContextRepository(
      InMemoryClientRegistrationRepository repository,
      JwtDecoder jwtDecoder,
      OAuth2AuthorizedClientService service) {
    return new JwtSecurityContextRepository(repository, jwtDecoder, service);
  }

  @Bean
  protected Customizer<RequestCacheConfigurer<HttpSecurity>> requestCacheCustomizer(
      RequestCache requestCache) {
    return (rc) -> rc.requestCache(requestCache);
  }

  @Bean
  protected RequestCache requestCache() {
    return new CookieRequestCache();
  }
}
