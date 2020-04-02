package org.hl7.cpcdsauthserver;

import java.util.UUID;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequestMapping("/register")
public class RegisterEndpoint {

    private static final Logger logger = ServerLogger.getLogger();

    @RequestMapping(value = "/user", method = RequestMethod.POST, consumes = { "application/json" })
    public ResponseEntity<String> RegisterUser(HttpServletRequest request, HttpEntity<String> entity) {
        logger.info("RegisterEndpoint::Register: /register/user");
        logger.log(Level.FINE, StringEscapeUtils.escapeJava(entity.getBody()));

        try {
            Gson gson = new GsonBuilder().setPrettyPrinting().create();
            User user = gson.fromJson(entity.getBody(), User.class);
            logger.log(Level.FINE, user.toString());

            String hashedPassword = BCrypt.hashpw(user.getPassword(), BCrypt.gensalt());
            User newUser = new User(user.getUsername(), hashedPassword, user.getPatientId());

            if (App.getDB().write(newUser))
                return new ResponseEntity<String>(gson.toJson(newUser.toMap()), HttpStatus.CREATED);
            else
                return new ResponseEntity<String>(HttpStatus.BAD_REQUEST);
        } catch (JsonSyntaxException e) {
            logger.log(Level.SEVERE, "RegisterEndpoint::RegisterUser:Unable to parse body", e);
            return new ResponseEntity<String>(HttpStatus.BAD_REQUEST);
        }
    }

    @RequestMapping(value = "/user", method = RequestMethod.GET)
    public String RegisterUserPage() {
        return "registerUser";
    }

    @RequestMapping(value = "/client", method = RequestMethod.POST)
    public ResponseEntity<String> RegisterClient(HttpServletRequest request, HttpEntity<String> entity,
            @RequestParam(name = "redirect_uri") String redirectUri) {
        // Escape all the query parameters
        redirectUri = StringEscapeUtils.escapeJava(redirectUri);

        logger.info("RegisterEndpoint::Register: /register/client");
        logger.log(Level.FINE, "RegisterClient:RedirectURI:" + redirectUri);

        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        String clientId = UUID.randomUUID().toString();
        String clientSecret = RandomStringUtils.randomAlphanumeric(256);
        Client newClient = new Client(clientId, clientSecret, redirectUri);

        if (App.getDB().write(newClient))
            return new ResponseEntity<String>(gson.toJson(newClient.toMap()), HttpStatus.CREATED);
        else
            return new ResponseEntity<String>(HttpStatus.BAD_REQUEST);

    }

    @RequestMapping(value = "/client", method = RequestMethod.GET)
    public String RegisterClientPage() {
        return "registerClient";
    }

}