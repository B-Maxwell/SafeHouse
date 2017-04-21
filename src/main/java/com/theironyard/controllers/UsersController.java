package com.theironyard.controllers;

import com.theironyard.entities.Response;
import com.theironyard.entities.User;
import com.theironyard.entities.Users;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
@RequestMapping("/users")
@CrossOrigin
public class UsersController {

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private Users users;

    // register a new user
    @RequestMapping(method = RequestMethod.POST)
    public ResponseEntity<?> addUser(@RequestBody Map<String, String> json) {
        String username = json.get("username");
        String password = json.get("password");
        String password2 = json.get("password2");

        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            return new ResponseEntity<>("Username and password must not be empty.", HttpStatus.BAD_REQUEST);
        }

        if (!password.equals(password2)) {
            return new ResponseEntity<>("Passwords do not match.", HttpStatus.BAD_REQUEST);
        }

        User user = new User(username, bCryptPasswordEncoder.encode(password));

        try {
            user = users.save(user);
            return new ResponseEntity<>(user, HttpStatus.OK);
        } catch (DataIntegrityViolationException e) {
            return new ResponseEntity<>("Invalid username or password", HttpStatus.BAD_REQUEST);
        }
    }

    // view current users
    @RequestMapping(path = "/current", method = RequestMethod.GET)
    public ResponseEntity<?> currentUser() {
        Authentication u = SecurityContextHolder.getContext().getAuthentication();
        String name = u.getName();
        User user = users.findByName(name);
        if (user != null) {
            return new ResponseEntity<>(user, HttpStatus.OK);
        }
        return new ResponseEntity<Object>("Invalid token.", HttpStatus.BAD_REQUEST);
    }

    // update username
    @RequestMapping(path = "/{userId}/username", method = RequestMethod.PATCH)
    public ResponseEntity<?> updateUserName(@PathVariable Integer userId,
                                            @RequestBody Map<String, String> json) {
        String newName = json.get("username");
        User user = users.findOne(userId);

        if (newName != null && !newName.isEmpty() && user != null) {
            user.setName(newName);
            users.save(user);
            return new ResponseEntity<>("Success", HttpStatus.OK);
        } else {
            return new ResponseEntity<>("Unable to change the user's name.", HttpStatus.BAD_REQUEST);
        }
    }

    // update password
    @RequestMapping(path = "/{userId}/password", method = RequestMethod.PATCH)
    public ResponseEntity<?> updatePassword(@PathVariable Integer userId,
                                            @RequestBody Map<String, String> json) {
        String newPW = json.get("newPassword");
        String newPW2 = json.get("newPassword2");
        String oldPW = json.get("oldPassword");
        User user = users.findOne(userId);

        String errorMsg;
        if (user != null) {
            if (newPW != null && !newPW.isEmpty() && newPW.equals(newPW2)) {
                if (bCryptPasswordEncoder.matches(oldPW, user.getPassword())) {
                    user.setPassword(bCryptPasswordEncoder.encode(newPW));
                    users.save(user);
                    return new ResponseEntity<>("Success", HttpStatus.OK);
                } else {
                    errorMsg = "Invalid old password.";
                }
            } else {
                errorMsg = "Invalid new password.";
            }
        } else {
            errorMsg = "Invalid user id.";
        }
        return new ResponseEntity<>(errorMsg, HttpStatus.BAD_REQUEST);
    }

    // delete account
    @RequestMapping(path = "/{userId}", method = RequestMethod.DELETE)
    public ResponseEntity<?> deleteAccount(@PathVariable Integer userId) {
        Response response = users.deleteAccount(userId);
        if (response.wasError) {
            return new ResponseEntity<>(response.errorMessage, response.status);
        } else {
            return new ResponseEntity<>(response.body, response.status);
        }
    }
}
