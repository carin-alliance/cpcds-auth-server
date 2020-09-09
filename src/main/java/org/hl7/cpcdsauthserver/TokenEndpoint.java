package org.hl7.cpcdsauthserver;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServletRequest;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.exceptions.SignatureVerificationException;
import com.auth0.jwt.exceptions.TokenExpiredException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.commons.text.StringEscapeUtils;
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

    private static final Logger logger = ServerLogger.getLogger();

    /**
     * Enum for types of tokens
     */
    public enum TokenType {
        REFRESH, ACCESS;
    }

    @PostMapping(value = "", params = { "grant_type", "code", "redirect_uri" })
    public ResponseEntity<String> Token(HttpServletRequest request, @RequestParam(name = "grant_type") String grantType,
            @RequestParam(name = "code") String code, @RequestParam(name = "redirect_uri") String redirectURI) {
        // Escape all the query parameters
        code = StringEscapeUtils.escapeJava(code);
        grantType = StringEscapeUtils.escapeJava(grantType);
        redirectURI = StringEscapeUtils.escapeJava(redirectURI);

        logger.info("TokenEndpoint::Token:Received request /token?grant_type=" + grantType + "&code=" + code
                + "&redirect_uri=" + redirectURI);
        return processRequest(request, grantType, code, redirectURI);
    }

    @PostMapping(value = "", params = { "grant_type", "refresh_token" })
    public ResponseEntity<String> Token(HttpServletRequest request, @RequestParam(name = "grant_type") String grantType,
            @RequestParam(name = "refresh_token") String refreshToken) {
        // Escape all the query parameters
        grantType = StringEscapeUtils.escapeJava(grantType);
        refreshToken = StringEscapeUtils.escapeJava(refreshToken);

        logger.info("TokenEndpoint::RefreshToken:Received request /token?grant_type=" + grantType + "&refresh_token="
                + refreshToken);
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
        String patientId = null;
        if (grantType.equals("authorization_code")) {
            // Request is to trade authorization_code for access token
            patientId = authCodeIsValid(token, baseUrl, redirectURI, clientId);
        } else if (grantType.equals("refresh_token")) {
            // Request is to trade refresh_token for access token
            patientId = refreshTokenIsValid(token, baseUrl, clientId);
        } else {
            response.put("error", "invalid_request");
            response.put("error_description", "grant_type must be authorization_code not " + grantType);
            return new ResponseEntity<String>(gson.toJson(response), headers, HttpStatus.BAD_REQUEST);
        }

        logger.log(Level.FINE, "TokenEndpoint::Token:Patient:" + patientId);
        if (patientId != null) {
            String accessToken = generateToken(token, baseUrl, clientId, patientId, UUID.randomUUID().toString(),
                    TokenType.ACCESS, request);
            logger.log(Level.FINE, "TokenEndpoint::Token:Generated token " + accessToken);
            if (accessToken != null) {
                String jwtId = UUID.randomUUID().toString();
                response.put("access_token", accessToken);
                response.put("token_type", "bearer");
                response.put("expires_in", "3600");
                response.put("patient", patientId);
                response.put("scope", "patient/*.read");
                response.put("refresh_token",
                        generateToken(token, baseUrl, clientId, patientId, jwtId, TokenType.REFRESH, request));
                App.getDB().setRefreshTokenId(patientId, jwtId);
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
     * header. Currently accepts all clients
     * 
     * @param request - the current request
     * @return the clientId from the authorization header
     */
    private String clientIsAuthorized(HttpServletRequest request) {
        String authHeader = request.getHeader("Authorization");
        logger.log(Level.FINE, "TokenEndpoint::AuthHeader:" + authHeader);
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
                    String clientId = clientAuthMatcher.group(1);
                    String clientSecret = clientAuthMatcher.group(2);
                    logger.log(Level.FINE, "TokenEndpoint::client:" + clientId + "(" + clientSecret + ")");
                    if (Client.getClient(clientId).validateSecret(clientSecret)) {
                        logger.info("TokenEndpoint::clientIsAuthorized:" + clientId);
                        return clientId;
                    }
                }
            }
        }
        logger.info("TokenEndpoint::clientIsAuthorized:false");
        return null;
    }

    /**
     * Generate an access (or request) token for the user with the correct claims.
     * Access token is valid for 1 hour
     * 
     * @param code      - the authorization code from the POST request
     * @param baseUrl   - the base url of this service
     * @param clientId  - the id of the requesting client
     * @param patientId - the user's patient ID
     * @param jwtId     - the unique id for this token
     * @param tokenType - the type of token to generate
     * @return access token for granted user or null
     */
    private String generateToken(String code, String baseUrl, String clientId, String patientId, String jwtId,
            TokenType tokenType, HttpServletRequest request) {
        try {
            // Create the access token JWT
            Algorithm algorithm = Algorithm.RSA256(App.getPublicKey(), App.getPrivateKey());
            String aud = tokenType == TokenType.ACCESS ? App.getEhrServer(request) : baseUrl;
            Instant exp = tokenType == TokenType.ACCESS
                    ? LocalDateTime.now().plusHours(1).atZone(ZoneId.systemDefault()).toInstant()
                    : LocalDateTime.now().plusDays(30).atZone(ZoneId.systemDefault()).toInstant();
            return JWT.create().withKeyId(App.getKeyId()).withIssuer(baseUrl).withExpiresAt(Date.from(exp))
                    .withIssuedAt(new Date()).withAudience(aud).withClaim("client_id", clientId)
                    .withClaim("patient_id", patientId).withJWTId(jwtId).sign(algorithm);
        } catch (JWTCreationException exception) {
            // Invalid Signing configuration / Couldn't convert Claims.
            logger.log(Level.SEVERE, "TokenEndpoint::generateToken:Unable to generate token", exception);
            return null;
        } catch (JWTVerificationException exception) {
            // Invalid code
            logger.log(Level.SEVERE, "TokenEndpoint::generateToken:Unable to verify code", exception);
            return null;
        }
    }

    /**
     * Validate/verify the authorization code is valid
     * 
     * @param code        - the authorization code
     * @param baseUrl     - the base URL of this service
     * @param redirectURI - the redirect_uri provided in the POST request
     * @return patientId if the authorization code is valid and null otherwise
     */
    private String authCodeIsValid(String code, String baseUrl, String redirectURI, String clientId) {
        String patientId = null;
        try {
            Algorithm algorithm = Algorithm.RSA256(App.getPublicKey(), null);
            JWTVerifier verifier = JWT.require(algorithm).withIssuer(baseUrl).withAudience(baseUrl)
                    .withClaim("redirect_uri", redirectURI).build();
            DecodedJWT jwt = verifier.verify(code);
            String jwtClientId = jwt.getClaim("client_id").asString();
            if (!clientId.equals(jwtClientId)) {
                logger.warning(
                        "TokenEndpoint::Authorization code is invalid. Client ID does not match authorization header");
            } else {
                String username = jwt.getClaim("username").asString();
                patientId = User.getUser(username).getPatientId();
            }
        } catch (SignatureVerificationException exception) {
            logger.log(Level.SEVERE, "TokenEndpoint::Authorization code is invalid. Signature invalid");
        } catch (TokenExpiredException exception) {
            logger.log(Level.SEVERE, "TokenEndpoint::Authorization code is invalid. Token expired");
        } catch (JWTVerificationException exception) {
            logger.log(Level.SEVERE, "TokenEndpoint::Authorization code is invalid. Please obtain a new code",
                    exception);
        }
        return patientId;
    }

    /**
     * Validate/verify the refresh token is valid
     * 
     * @param token   - the refresg token
     * @param baseUrl - the base URL of this service
     * @return patientId if the refresh token is valid and null otherwise
     */
    private String refreshTokenIsValid(String code, String baseUrl, String clientId) {
        String patientId = null;
        try {
            Algorithm algorithm = Algorithm.RSA256(App.getPublicKey(), null);
            JWTVerifier verifier = JWT.require(algorithm).withIssuer(baseUrl).withAudience(baseUrl).build();
            DecodedJWT jwt = verifier.verify(code);
            String jwtId = jwt.getId();
            String jwtClientId = jwt.getClaim("client_id").asString();
            if (!clientId.equals(jwtClientId)) {
                logger.warning(
                        "TokenEndpoint::Refresh token is invalid. Client ID does not match authorization header");
                return null;
            }

            patientId = jwt.getClaim("patient_id").asString();
            if (!jwtId.equals(App.getDB().readRefreshToken(patientId))) {
                logger.warning("TokenEndpoint::Refresh token is invalid. Please reauthorize");
                return null;
            }
        } catch (JWTVerificationException exception) {
            logger.log(Level.SEVERE, "TokenEndpoint::Refresh token is invalid. Please reauthorize", exception);
        }
        return patientId;
    }
}
