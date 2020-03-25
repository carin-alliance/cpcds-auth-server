package org.hl7.cpcdsauthserver;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

/**
 * Authorization endpoint for client to obtain an authorization code
 */
@Controller
public class AuthorizationEndpoint {

  private static final Logger logger = ServerLogger.getLogger();

  @RequestMapping(value = "/authorization", params = { "response_type", "client_id", "redirect_uri", "scope", "state",
      "aud" })
  public String Authorization(@RequestParam(name = "response_type") String responseType,
      @RequestParam(name = "client_id") String clientId, @RequestParam(name = "redirect_uri") String redirectURI,
      @RequestParam(name = "scope") String scope, @RequestParam(name = "state") String state,
      @RequestParam(name = "aud") String aud) {
    logger.info(
        "AuthorizationEndpoint::Authorization:Received /authorization?response_type=" + responseType + "&client_id="
            + clientId + "&redirect_uri=" + redirectURI + "&scope=" + scope + "&state=" + state + "&aud=" + aud);

    return "login";
  }

  @RequestMapping(value = "/authorization", params = { "response_type", "client_id", "redirect_uri", "scope", "state",
      "aud", "username", "password" })
  public RedirectView Authorization(HttpServletRequest request, RedirectAttributes attributes,
      @RequestParam(name = "response_type") String responseType, @RequestParam(name = "client_id") String clientId,
      @RequestParam(name = "redirect_uri") String redirectURI, @RequestParam(name = "scope") String scope,
      @RequestParam(name = "state") String state, @RequestParam(name = "aud") String aud,
      @RequestParam(name = "username") String username, @RequestParam(name = "password") String password) {
    logger.info("AuthorizationEndpoint::Authorization:Received /authorization?response_type=" + responseType
        + "&client_id=" + clientId + "&redirect_uri=" + redirectURI + "&scope=" + scope + "&state=" + state + "&aud="
        + aud + "&username=" + username + "&password=" + password);
    final String baseUrl = App.getServiceBaseUrl(request);

    if (!aud.equals(App.getEhrServer())) {
      attributes.addAttribute("error", "invalid_request");
      attributes.addAttribute("error_description", "aud is invalid");
    } else if (!responseType.equals("code")) {
      attributes.addAttribute("error", "invalid_request");
      attributes.addAttribute("error_description", "response_type must be code");
    } else if (Client.getClient(clientId) == null) {
      attributes.addAttribute("error", "unauthorized_client");
      attributes.addAttribute("error_description", "client is not registered");
    } else {
      User user = User.getUser(username);
      if (user == null) {
        attributes.addAttribute("error", "access_denied");
        attributes.addAttribute("error_description", "user does not exist");
      } else if (user.validatePassword(password)) {
        logger.info("AuthorizationEndpoint::User " + username + " is authorized");

        String code = generateAuthorizationCode(baseUrl, clientId, redirectURI, username);
        logger.info("AuthorizationEndpoint::Generated code " + code);
        if (code == null) {
          attributes.addAttribute("error", "server_error");
        } else {
          attributes.addAttribute("code", code);
          attributes.addAttribute("state", state);
        }
      } else {
        attributes.addAttribute("error", "access_denied");
        attributes.addAttribute("error_description", "invalid username/password");
      }
    }

    logger.info("Redirecting to " + redirectURI + attributes.toString());
    return new RedirectView(redirectURI);
  }

  /**
   * Generate the Authorization code for the client with a 2 minute expiration
   * time
   * 
   * @param baseUrl     - the baseUrl for this service
   * @param clientId    - the client_id received in the GET request
   * @param redirectURI - the redirect_uri received in the GET request
   * @param username    - the user's log in username
   * @return signed JWT token for the authorization code
   */
  private String generateAuthorizationCode(String baseUrl, String clientId, String redirectURI, String username) {
    try {
      Algorithm algorithm = Algorithm.RSA256(App.getPublicKey(), App.getPrivateKey());
      Instant twoMinutes = LocalDateTime.now().plusMinutes(2).atZone(ZoneId.systemDefault()).toInstant();
      return JWT.create().withIssuer(baseUrl).withExpiresAt(Date.from(twoMinutes)).withIssuedAt(new Date())
          .withAudience(baseUrl).withClaim("client_id", clientId).withClaim("redirect_uri", redirectURI)
          .withClaim("username", username).sign(algorithm);
    } catch (JWTCreationException exception) {
      // Invalid Signing configuration / Couldn't convert Claims.
      logger.log(Level.SEVERE,
          "AuthorizationEndpoint::generateAuthorizationCode:Unable to generate code for " + clientId, exception);
      return null;
    }
  }

}
