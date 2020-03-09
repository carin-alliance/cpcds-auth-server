package org.hl7.cpcdsauthserver;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin
@RestController
@RequestMapping("/debug")
public class DebugEndpoint {

    @GetMapping("/Users")
    public ResponseEntity<String> getUsers() {
        System.out.println("GET /debug/Users");
        return new ResponseEntity<>(App.getDB().generateAndRunQuery(), HttpStatus.OK);
    }
}