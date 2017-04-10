package com.theironyard.controllers;


import com.theironyard.entities.House;
import com.theironyard.entities.Item;
import com.theironyard.entities.User;
import com.theironyard.services.HouseRepository;
import com.theironyard.services.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;


import java.util.List;
import java.util.Map;

@RestController
public class SafeHouseController {

    @Autowired
    private UserRepository users;
    @Autowired
    private HouseRepository houses;

    // register a new user
    @RequestMapping(path = "/users", method = RequestMethod.POST)
    public ResponseEntity<?> addUser(@RequestBody Map<String, String> json) {
        String username = json.get("username");
        String password = json.get("password");

        try {
            User user = new User(username, password); // throws IllegalArgumentException on bad UN or PW
            users.save(user);
            return new ResponseEntity<>(user, HttpStatus.OK);
        } catch (DataIntegrityViolationException | IllegalArgumentException e) {
            return new ResponseEntity<>("Invalid username or password.", HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            e.printStackTrace();
            return new ResponseEntity<>("Problem", HttpStatus.BAD_REQUEST);
        }
    }

    // user login
    @RequestMapping(path = "/login", method = RequestMethod.POST)
    public /*ResponseEntity<?>*/String login(/*@RequestBody Map<String, String> json*/) {

//        String username = json.get("username");
//        String password = json.get("password");
//
//        System.out.println("Username: " + username);
//        System.out.println("Password: " + password);
//
//        if ((username != null && !username.isEmpty()) && (password != null && !password.isEmpty())) {
//            User user = users.findOneByName(username);
//            if (user != null) {
//                if (user.verifyPassword(password)) {
//                    return new ResponseEntity<>( HttpStatus.OK);
//                }
//            }
//        }
//        return new ResponseEntity<>("Bad login.", HttpStatus.UNAUTHORIZED);
        return "Success";
    }

    // return user's houses Todo
    @RequestMapping(path = "/houses", method = RequestMethod.GET)
    public List<House> getHouses() {
        return null;
    }

    // add a new house Todo
    @RequestMapping(path = "/houses", method = RequestMethod.POST)
    public void addHouse(@RequestBody Map<String, String> json) {
        String username = json.get("username");
        String houseName = json.get("houseName");

        User user = users.findOneByName(username);
        houses.save(new House(houseName, user));
    }

    // get user Todo
    @RequestMapping(path = "/user", method = RequestMethod.GET)
    public void getUser(@RequestBody Map<String, String> json) {
        System.out.println(json);
    }

    // get house Todo
    @RequestMapping(path = "/house", method = RequestMethod.GET)
    public void getHouse(@RequestBody Map<String, String> json) {
        System.out.println(json);
    }

    // remove a house Todo
    @RequestMapping(path = "/house", method = RequestMethod.DELETE)
    public void deleteHouse(@RequestBody Map<String, String> json) {
        System.out.println(json);
    }

    // add item to house Todo
    @RequestMapping(path = "/item", method = RequestMethod.POST)
    public void addItem(@RequestBody Map<String, String> json) {
        String username = json.get("username");
        String houseName = json.get("houseName");
        String itemName = json.get("itemName");

        House house = houses.findOneByNameAndUser_Name(houseName, username);
        System.out.println(house.getName());
        house.addItem(new Item(itemName));
        houses.save(house);
    }

    // remove item from house Todo
    @RequestMapping(path = "/item", method = RequestMethod.DELETE)
    public void deleteItem(@RequestBody Map<String, String> json) {
        System.out.println(json);
    }

    // get items from search Todo
    @RequestMapping(path = "/items", method = RequestMethod.GET)
    public void getItems(@RequestBody Map<String, String> json) {
        System.out.println(json);

    }
}
