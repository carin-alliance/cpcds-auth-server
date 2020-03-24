package org.hl7.cpcdsauthserver;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Token endpoint to exchange an authorization code for an access token
 */
@CrossOrigin
@RestController
@RequestMapping("/.well-known")
public class RSAKeys {

    private static final Logger logger = ServerLogger.getLogger();

    @GetMapping(value = "/jwks.json")
    public ResponseEntity<String> Keys(HttpServletRequest request) {
        logger.info("GET /.well-known/jwks.json");

        // Set the headers for the response
        MultiValueMap<String, String> headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_TYPE, "application/json");

        // Set the response
        HashMap<String, String> key = new HashMap<String, String>();
        HashMap<String, List<HashMap<String, String>>> response = new HashMap<String, List<HashMap<String, String>>>();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        key.put("alg", "RS256");
        key.put("kty", "RSA");
        key.put("use", "sig");
        key.put("n", App.getPublicKey().getModulus().toString(64));
        key.put("e", App.getPublicKey().getPublicExponent().toString(64));
        key.put("kid", App.getKeyId());
        response.put("keys", Collections.singletonList(key));

        return new ResponseEntity<String>(gson.toJson(response), headers, HttpStatus.OK);
    }
}