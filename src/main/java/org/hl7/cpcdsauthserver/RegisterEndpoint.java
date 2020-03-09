package org.hl7.cpcdsauthserver;

import java.security.NoSuchAlgorithmException;

import javax.servlet.http.HttpServletRequest;

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

    @PostMapping("")
    public ResponseEntity<String> Register(HttpServletRequest request, @RequestParam(name = "username") String username,
            @RequestParam(name = "password") String password, @RequestParam(name = "id") String id)
            throws NoSuchAlgorithmException {
        System.out.println(
                "RegisterEndpoint::Register: /register?username=" + username + "&password=" + password + "&id=" + id);

        String r = PasswordUtils.generateSalt(10);
        String hashedPassword = PasswordUtils.hashPassword(password, r);
        User user = new User(username, hashedPassword, id, r);

        if (App.getDB().write(user))
            return new ResponseEntity<String>("Success", HttpStatus.CREATED);
        else
            return new ResponseEntity<String>("ERROR", HttpStatus.BAD_REQUEST);

    }
}