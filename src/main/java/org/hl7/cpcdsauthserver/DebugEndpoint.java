package org.hl7.cpcdsauthserver;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.hl7.cpcdsauthserver.Database.Table;
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

    private static final Logger logger = ServerLogger.getLogger();

    @GetMapping("/Users")
    public ResponseEntity<String> getUsers() {
        logger.info("GET /debug/Users");
        return new ResponseEntity<>(App.getDB().generateAndRunQuery(Table.USERS), HttpStatus.OK);
    }

    @GetMapping("/Clients")
    public ResponseEntity<String> getClients() {
        logger.info("GET /debug/Clients");
        return new ResponseEntity<>(App.getDB().generateAndRunQuery(Table.CLIENTS), HttpStatus.OK);
    }

    @GetMapping("/Log")
    public ResponseEntity<String> getLog() {
        logger.info("GET /debug/Log");
        try {
            String log = new String(Files.readAllBytes(Paths.get(ServerLogger.getLogPath())));
            return new ResponseEntity<>(log, HttpStatus.OK);
        } catch (IOException e) {
            logger.log(Level.SEVERE, "DebugEndpoint::Log:IOException", e);
            return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
        }
    }
}