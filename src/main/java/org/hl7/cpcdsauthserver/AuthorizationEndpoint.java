package org.hl7.cpcdsauthserver;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.commons.text.StringEscapeUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

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
    // Escape all the query parameters
    aud = StringEscapeUtils.escapeJava(aud);
    scope = StringEscapeUtils.escapeJava(scope);
    state = StringEscapeUtils.escapeJava(state);
    clientId = StringEscapeUtils.escapeJava(clientId);
    redirectURI = StringEscapeUtils.escapeJava(redirectURI);
    responseType = StringEscapeUtils.escapeJava(responseType);

    logger.info(
        "AuthorizationEndpoint::Authorization:Received /authorization?response_type=" + responseType + "&client_id="
            + clientId + "&redirect_uri=" + redirectURI + "&scope=" + scope + "&state=" + state + "&aud=" + aud);

    return "login";
  }

  @RequestMapping(value = "/authorization", method = RequestMethod.POST, params = { "response_type", "client_id",
      "redirect_uri", "scope", "state", "aud" })
  public ResponseEntity<String> Authorization(HttpServletRequest request, HttpEntity<String> entity,
      @RequestParam(name = "response_type") String responseType, @RequestParam(name = "client_id") String clientId,
      @RequestParam(name = "redirect_uri") String redirectURI, @RequestParam(name = "scope") String scope,
      @RequestParam(name = "state") String state, @RequestParam(name = "aud") String aud) {
    // Escape all the query parameters
    aud = StringEscapeUtils.escapeJava(aud);
    scope = StringEscapeUtils.escapeJava(scope);
    state = StringEscapeUtils.escapeJava(state);
    clientId = StringEscapeUtils.escapeJava(clientId);
    redirectURI = StringEscapeUtils.escapeJava(redirectURI);
    responseType = StringEscapeUtils.escapeJava(responseType);

    logger.info(
        "AuthorizationEndpoint::Authorization:Received /authorization?response_type=" + responseType + "&client_id="
            + clientId + "&redirect_uri=" + redirectURI + "&scope=" + scope + "&state=" + state + "&aud=" + aud);
    final String baseUrl = App.getServiceBaseUrl(request);
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    HashMap<String, String> attributes = new HashMap<String, String>();

    HttpStatus status = HttpStatus.OK;
    if (!aud.equals(App.getEhrServer(request))) {
      status = HttpStatus.BAD_REQUEST;
      attributes.put("error", "invalid_request");
      attributes.put("error_description", "aud is invalid");
    } else if (!responseType.equals("code")) {
      status = HttpStatus.BAD_REQUEST;
      attributes.put("error", "invalid_request");
      attributes.put("error_description", "response_type must be code");
    } else if (Client.getClient(clientId) == null) {
      status = HttpStatus.BAD_REQUEST;
      attributes.put("error", "unauthorized_client");
      attributes.put("error_description", "client is not registered");
    } else {
      User userRequest = gson.fromJson(entity.getBody(), User.class);
      logger.info("AuthorizationEndpoint::Authorization:Received login request from " + userRequest.getUsername());
      User user = App.getDB().readUser(userRequest.getUsername());
      if (user == null) {
        status = HttpStatus.BAD_REQUEST;
        attributes.put("error", "access_denied");
        attributes.put("error_description", "user does not exist");
      } else if (BCrypt.checkpw(userRequest.getPassword(), user.getPassword())) {
        logger.info("AuthorizationEndpoint::User " + user.getUsername() + " is authorized");

        String code = generateAuthorizationCode(baseUrl, clientId, redirectURI, user.getUsername());
        logger.info("AuthorizationEndpoint::Generated code " + code);
        if (code == null) {
          status = HttpStatus.INTERNAL_SERVER_ERROR;
          attributes.put("error", "server_error");
        } else {
          attributes.put("code", code);
          attributes.put("state", state);
        }
      } else {
        status = HttpStatus.UNAUTHORIZED;
        attributes.put("error", "access_denied");
        attributes.put("error_description", "invalid username/password");
        logger.severe("AuthorizationEndpoint::Authorization:Failed loging attempt from " + user.getUsername());
      }
    }

    redirectURI = getRedirect(redirectURI, attributes);
    logger.info("Redirecting to " + redirectURI);
    return new ResponseEntity<String>(gson.toJson(Collections.singletonMap("redirect", redirectURI)), status);
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

  /**
   * Simple method to produce the redirect uri from the attributes
   * 
   * @param redirectURI - the base redirect uri
   * @param attributes  - the attributes to add to the base redirect uri
   * @return formatted redirect uri
   */
  private String getRedirect(String redirectURI, Map<String, String> attributes) {
    if (attributes.size() > 0) {
      redirectURI += "?";

      int i = 1;
      for (Map.Entry<String, String> entry : attributes.entrySet()) {
        redirectURI += entry.getKey() + "=" + entry.getValue();

        if (i != attributes.size())
          redirectURI += "&";

        i++;
      }
    }

    return redirectURI;
  }

}
