package org.hl7.cpcdsauthserver;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * Token endpoint to exchange an authorization code for an access token
 */
@CrossOrigin
@RestController
@RequestMapping("/token")
public class TokenEndpoint {

    /**
     * Enum for types of tokens
     */
    public enum TokenType {
        REFRESH, ACCESS;
    }

    @PostMapping(value = "", params = { "grant_type", "code", "redirect_uri" })
    public ResponseEntity<String> Token(HttpServletRequest request, @RequestParam(name = "grant_type") String grantType,
            @RequestParam(name = "code") String code, @RequestParam(name = "redirect_uri") String redirectURI) {
        System.out.println("TokenEndpoint::Token:Received request /token?grant_type=" + grantType + "&code=" + code
                + "&redirect_uri=" + redirectURI);
        return processRequest(request, grantType, code, redirectURI);
    }

    @PostMapping(value = "", params = { "grant_type", "refresh_token" })
    public ResponseEntity<String> Token(HttpServletRequest request, @RequestParam(name = "grant_type") String grantType,
            @RequestParam(name = "refresh_token") String refreshToken) {
        System.out.println("TokenEndpoint::RefreshToken:Received request /token?grant_type=" + grantType
                + "&refresh_token=" + refreshToken);
        return processRequest(request, grantType, refreshToken, null);
    }

    private ResponseEntity<String> processRequest(HttpServletRequest request, String grantType, String token,
            String redirectURI) {
        // Set the headers for the response
        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.add(HttpHeaders.CACHE_CONTROL, "no-store");
        headers.add(HttpHeaders.PRAGMA, "no-store");

        HashMap<String, String> response = new HashMap<String, String>();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        String baseUrl = App.getServiceBaseUrl(request);

        // Validate the client is authorized
        String clientId = clientIsAuthorized(request);
        if (clientId == null) {
            response.put("error", "invalid_client");
            response.put("error-description",
                    "Authorization header is missing, malformed, or client_id/client_secret is invalid");
            return new ResponseEntity<String>(gson.toJson(response), headers, HttpStatus.UNAUTHORIZED);
        }

        // Validate the grant_type is authorization_code or refresh_token
        boolean tokenIsValid = false;
        if (grantType.equals("authorization_code")) {
            // Request is to trade authorization_code for access token
            tokenIsValid = authCodeIsValid(token, baseUrl, redirectURI, clientId);
        } else if (grantType.equals("refresh_token")) {
            // Request is to trade refresh_token for access token
            tokenIsValid = refreshTokenIsValid(token, baseUrl, clientId);
        } else {
            response.put("error", "invalid_request");
            response.put("error_description", "grant_type must be authorization_code not " + grantType);
            return new ResponseEntity<String>(gson.toJson(response), headers, HttpStatus.BAD_REQUEST);
        }

        if (tokenIsValid) {
            String accessToken = generateToken(token, baseUrl, clientId, UUID.randomUUID().toString(),
                    TokenType.ACCESS);
            System.out.println("TokenEndpoint::Token:Generated token " + accessToken);
            if (accessToken != null) {
                String jwtId = UUID.randomUUID().toString();
                response.put("access_token", accessToken);
                response.put("token_type", "bearer");
                response.put("expires_in", "3600");
                response.put("scope", "patient/*.read");
                response.put("refresh_token", generateToken(token, baseUrl, clientId, jwtId, TokenType.REFRESH));
                // TODO: post jwtID to database
                return new ResponseEntity<String>(gson.toJson(response), headers, HttpStatus.OK);
            } else {
                response.put("error", "invalid_request");
                response.put("error_description", "Internal server error. Please try again");
                return new ResponseEntity<String>(gson.toJson(response), headers, HttpStatus.INTERNAL_SERVER_ERROR);
            }
        } else {
            response.put("error", "invalid_grant");
            response.put("error_description", "Unable to verify. Please make sure the code/token is still valid");
            return new ResponseEntity<String>(gson.toJson(response), headers, HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Determine if the client is authorized based on the Basic Authorization
     * header. Validates against the user's password
     * 
     * @param request - the current request
     * @return client id if the Authorization header is present and formatted
     *         correctly. Null otherwise.
     */
    private String clientIsAuthorized(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        if (authHeader != null) {
            String regex = "Basic (.*)";
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(authHeader);
            if (matcher.find() && matcher.groupCount() == 1) {
                String clientAuthorization = new String(Base64.getDecoder().decode(matcher.group(1)));
                String clientAuthRegex = "(.*):(.*)";
                Pattern clientAuthPattern = Pattern.compile(clientAuthRegex);
                Matcher clientAuthMatcher = clientAuthPattern.matcher(clientAuthorization);
                if (clientAuthMatcher.find() && clientAuthMatcher.groupCount() == 2) {
                    String clientUsername = clientAuthMatcher.group(1);
                    String clientSecret = clientAuthMatcher.group(2);
                    if (clientUsername != null && clientSecret != null) {
                        User user = App.getDB().read(clientUsername);
                        if (user.validatePassword(clientSecret)) {
                            System.out.println("TokenEndpoint::clientIsAuthorized:" + clientUsername);
                            return user.getId();
                        }
                    }
                }
            }
        }
        System.out.println("TokenEndpoint::clientIsAuthorized:false");
        return null;
    }

    /**
     * Generate an access (or request) token for the user with the correct claims.
     * Access token is valid for 1 hour
     * 
     * @param code      - the authorization code from the POST request
     * @param baseUrl   - the base url of this service
     * @param clientId  - the client id
     * @param jwtId     - the unique id for this token
     * @param tokenType - the type of token to generate
     * @return access token for granted user or null
     */
    private String generateToken(String code, String baseUrl, String clientId, String jwtId, TokenType tokenType) {
        try {
            // Create the access token JWT
            Algorithm algorithm = Algorithm.HMAC256(App.getSecret());
            String aud = tokenType == TokenType.ACCESS ? App.getEhrServer() : baseUrl;
            Instant exp = tokenType == TokenType.ACCESS
                    ? LocalDateTime.now().plusHours(1).atZone(ZoneId.systemDefault()).toInstant()
                    : LocalDateTime.now().plusDays(30).atZone(ZoneId.systemDefault()).toInstant();
            return JWT.create().withIssuer(baseUrl).withExpiresAt(Date.from(exp)).withIssuedAt(new Date())
                    .withAudience(aud).withClaim("client_id", clientId).withJWTId(jwtId).sign(algorithm);
        } catch (JWTCreationException exception) {
            // Invalid Signing configuration / Couldn't convert Claims.
            System.out.println("TokenEndpoint::generateToken:Unable to generate token");
            return null;
        } catch (JWTVerificationException exception) {
            // Invalid code
            System.out.println("TokenEndpoint::generateToken:Unable to verify code");
            return null;
        }
    }

    /**
     * Validate/verify the authorization code is valid
     * 
     * @param code        - the authorization code
     * @param baseUrl     - the base URL of this service
     * @param redirectURI - the redirect_uri provided in the POST request
     * @return true if the authorization code is valid and false otherwise
     */
    private boolean authCodeIsValid(String code, String baseUrl, String redirectURI, String clientId) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(App.getSecret());
            JWTVerifier verifier = JWT.require(algorithm).withIssuer(baseUrl).withAudience(baseUrl)
                    .withClaim("redirect_uri", redirectURI).build();
            DecodedJWT jwt = verifier.verify(code);
            String clientUsername = jwt.getClaim("client_username").asString();
            User client = User.getUser(clientUsername);
            if (!clientId.equals(client.getId())) {
                System.out.println(
                        "TokenEndpoint::Authorization code is invalid. Client ID does not match authorization header");
                return false;
            }
        } catch (JWTVerificationException exception) {
            System.out.println("TokenEndpoint::Authorization code is invalid. Please obtain a new code");
            return false;
        }
        return true;
    }

    /**
     * Validate/verify the refresh token is valid
     * 
     * @param token   - the refresg token
     * @param baseUrl - the base URL of this service
     * @return true if the refresh token is valid and false otherwise
     */
    private boolean refreshTokenIsValid(String code, String baseUrl, String clientId) {
        // TODO: validate the jwt ID is still valid
        try {
            Algorithm algorithm = Algorithm.HMAC256(App.getSecret());
            JWTVerifier verifier = JWT.require(algorithm).withIssuer(baseUrl).withAudience(baseUrl).build();
            DecodedJWT jwt = verifier.verify(code);
            String jwtClientId = jwt.getClaim("client_id").asString();
            if (!clientId.equals(jwtClientId)) {
                System.out.println(
                        "TokenEndpoint::Refresh token is invalid. Client ID does not match authorization header");
                return false;
            }
        } catch (JWTVerificationException exception) {
            System.out.println("TokenEndpoint::Refresh token is invalid. Please reauthorize");
            return false;
        }
        return true;
    }
}
