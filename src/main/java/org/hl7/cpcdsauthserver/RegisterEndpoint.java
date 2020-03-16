package org.hl7.cpcdsauthserver;

import java.util.HashMap;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin
@RestController
@RequestMapping("/register")
public class RegisterEndpoint {

    @PostMapping("/user")
    public ResponseEntity<String> RegisterUser(HttpServletRequest request,
            @RequestParam(name = "username") String username, @RequestParam(name = "password") String password,
            @RequestParam(name = "patientId") String patientId) {
        System.out.println("RegisterEndpoint::Register: /register/user?username=" + username + "&password=" + password
                + "&patientId=" + patientId);

        String r = PasswordUtils.generateSalt(10);
        String hashedPassword = PasswordUtils.hashPassword(password, r);
        User user = new User(username, hashedPassword, patientId, r);

        if (App.getDB().write(user))
            return new ResponseEntity<String>("Success", HttpStatus.CREATED);
        else
            return new ResponseEntity<String>("ERROR", HttpStatus.BAD_REQUEST);

    }

    @PostMapping("/client")
    public ResponseEntity<String> RegisterClient(HttpServletRequest request) {
        System.out.println("RegisterEndpoint::Register: /register/client");

        HashMap<String, String> response = new HashMap<String, String>();
        Gson gson = new GsonBuilder().setPrettyPrinting().create();

        String clientId = UUID.randomUUID().toString();
        String clientSecret = RandomStringUtils.randomAlphanumeric(256);
        response.put("id", clientId);
        response.put("secret", clientSecret);

        if (App.getDB().write(clientId, clientSecret))
            return new ResponseEntity<String>(gson.toJson(response), HttpStatus.CREATED);
        else
            return new ResponseEntity<String>("ERROR", HttpStatus.BAD_REQUEST);

    }
}