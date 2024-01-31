package space.keshway.authentication.client;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Optional;

public final class CookieHelper {

  public static final String DEFAULT_CONTEXT_PATH = "/";

  public static void addCookie(
      HttpServletRequest request,
      HttpServletResponse response,
      String name,
      String value,
      Instant expiresAt) {
    final Cookie cookie = new Cookie(name, value);
    cookie.setMaxAge((int) Duration.between(Instant.now(), expiresAt).getSeconds());
    cookie.setPath(getRequestContext(request));
    cookie.setSecure(request.isSecure());
    cookie.setHttpOnly(true);
    response.addCookie(cookie);
  }

  public static Optional<Cookie> getCookie(HttpServletRequest request, String name) {
    if (request == null) return Optional.empty();
    if (request.getCookies() == null || request.getCookies().length == 0) return Optional.empty();
    return Arrays.stream(request.getCookies()).filter(c -> c.getName().equals(name)).findFirst();
  }

  private static String getRequestContext(HttpServletRequest request) {
    String contextPath = request.getContextPath();
    return contextPath.isEmpty() ? DEFAULT_CONTEXT_PATH : contextPath;
  }
}
