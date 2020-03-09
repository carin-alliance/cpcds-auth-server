package org.hl7.cpcdsauthserver;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;
import org.springframework.web.servlet.view.RedirectView;

/**
 * Authorization endpoint for client to obtain an authorization code
 */
@CrossOrigin
@RestController
@RequestMapping("/authorization")
public class AuthorizationEndpoint {

  @GetMapping(value = "")
  public RedirectView Authorization(HttpServletRequest request, RedirectAttributes attributes,
      @RequestParam(name = "response_type") String responseType, @RequestParam(name = "client_id") String clientId,
      @RequestParam(name = "redirect_uri") String redirectURI, @RequestParam(name = "scope") String scope,
      @RequestParam(name = "state") String state, @RequestParam(name = "aud") String aud) {
    System.out.println(
        "AuthorizationEndpoint::Authorization:Received /authorization?response_type=" + responseType + "&client_id="
            + clientId + "&redirect_uri=" + redirectURI + "&scope=" + scope + "&state=" + state + "&aud=" + aud);
    final String baseUrl = App.getServiceBaseUrl(request);

    // Validate request and set URI params appropriately
    if (!aud.equals(App.getEhrServer())) // Validate the audience matches the server url
      attributes.addAttribute("error", "invalid_request");
    else if (!responseType.equals("code")) // Validate the response_type is code
      attributes.addAttribute("error", "invalid_request");
    else {
      String code = generateAuthorizationCode(baseUrl, clientId, redirectURI, aud);
      System.out.println("AuthorizationEndpoint::Generated code " + code);
      if (code != null) {
        attributes.addAttribute("code", code);
        attributes.addAttribute("state", state);
      } else
        attributes.addAttribute("error", "server_error");
    }

    return new RedirectView(redirectURI);
  }

  @GetMapping(value = "/test")
  public ResponseEntity<String> AuthorizationTest(HttpServletRequest request,
      @RequestParam(name = "response_type") String responseType, @RequestParam(name = "client_id") String clientId,
      @RequestParam(name = "redirect_uri") String redirectURI, @RequestParam(name = "scope") String scope,
      @RequestParam(name = "state") String state, @RequestParam(name = "aud") String aud) {
    System.out.println(
        "AuthorizationEndpoint::Authorization:Received /authorization?response_type=" + responseType + "&client_id="
            + clientId + "&redirect_uri=" + redirectURI + "&scope=" + scope + "&state=" + state + "&aud=" + aud);
    final String baseUrl = App.getServiceBaseUrl(request);

    // Validate the audience matches the server url
    if (!aud.equals(App.getEhrServer())) // Validate the audience matches the server url
      return new ResponseEntity<String>("Invalid audience", HttpStatus.BAD_REQUEST);

    // Validate the response_type is code
    if (!responseType.equals("code"))
      return new ResponseEntity<String>("Invalid response_type. Must be code", HttpStatus.BAD_REQUEST);

    HashMap<String, String> response = new HashMap<String, String>();
    response.put("redirectURI", redirectURI);
    response.put("code", generateAuthorizationCode(baseUrl, clientId, redirectURI, aud));
    response.put("state", state);
    Gson gson = new GsonBuilder().setPrettyPrinting().create();
    return new ResponseEntity<String>(gson.toJson(response), HttpStatus.OK);
  }

  /**
   * Generate the Authorization code for the client with a 2 minute expiration
   * time
   * 
   * @param baseUrl     - the baseUrl for this service
   * @param clientId    - the client_id received in the GET request
   * @param redirectURI - the redirect_uri received in the GET request
   * @param aud         - the aud received in the GET request
   * @return signed JWT token for the authorization code
   */
  private String generateAuthorizationCode(String baseUrl, String clientId, String redirectURI, String aud) {
    try {
      Algorithm algorithm = Algorithm.HMAC256(App.getSecret());
      Instant twoMinutes = LocalDateTime.now().plusMinutes(2).atZone(ZoneId.systemDefault()).toInstant();
      return JWT.create().withIssuer(baseUrl).withExpiresAt(Date.from(twoMinutes)).withAudience(aud)
          .withClaim("client_id", clientId).withClaim("redirect_uri", redirectURI).sign(algorithm);
    } catch (JWTCreationException exception) {
      // Invalid Signing configuration / Couldn't convert Claims.
      System.out.println("AuthorizationEndpoint::generateAuthorizationCode:Unable to generate code for " + clientId);
      return null;
    }
  }
}
