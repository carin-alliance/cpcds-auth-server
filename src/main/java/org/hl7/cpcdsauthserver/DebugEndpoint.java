package org.hl7.cpcdsauthserver;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;

import org.apache.commons.text.StringEscapeUtils;
import org.hl7.cpcdsauthserver.Database.Table;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
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

    @RequestMapping(value = "/register/client", method = RequestMethod.POST, consumes = { "application/json" })
    public ResponseEntity<String> RegisterClient(HttpServletRequest request, HttpEntity<String> entity) {
        logger.info("DebugEndpoint::DebugRegister: /register/client");
        logger.log(Level.FINE, StringEscapeUtils.escapeJava(entity.getBody()));

        try {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        Client client = gson.fromJson(entity.getBody(), Client.class);
        logger.log(Level.FINE, client.toString());
        if (App.getDB().write(client))
            return new ResponseEntity<String>(gson.toJson(client.toMap()), HttpStatus.CREATED);
        else
            return new ResponseEntity<String>(HttpStatus.BAD_REQUEST);
        } catch(JsonSyntaxException e) {
            logger.log(Level.SEVERE, "DebugEndpoint::RegisterUser:Unable to parse body", e);
            return new ResponseEntity<String>(HttpStatus.BAD_REQUEST);
        }
    }
}