package space.keshway.authentication.client;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@Getter
enum CookieType {
  AUTHORIZATION("TOKEN");

  private final String name;
}
