package com.theironyard.controllers;


import com.theironyard.entities.House;
import com.theironyard.entities.HouseHoldItem;
import com.theironyard.entities.Item;
import com.theironyard.entities.SearchItem;
import com.theironyard.entities.User;
import com.theironyard.services.HouseHoldItemRepository;
import com.theironyard.services.HouseRepository;
import com.theironyard.services.ItemRepository;
import com.theironyard.services.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@CrossOrigin
@RestController
public class SafeHouseController {

    @Autowired
    private UserRepository users;
    @Autowired
    private HouseRepository houses;
    @Autowired
    private HouseHoldItemRepository houseHoldItems;
    @Autowired
    private ItemRepository items;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    // register a new user
    @RequestMapping(path = "/users", method = RequestMethod.POST)
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
            users.save(user);
            return new ResponseEntity<>(user, HttpStatus.OK);
        } catch (DataIntegrityViolationException e) {
            return new ResponseEntity<>("Invalid username or password", HttpStatus.BAD_REQUEST);
        }
    }

    // view current users
    @RequestMapping(path = "/users/current", method = RequestMethod.GET)
    public ResponseEntity<?> currentUser() {
        Authentication u = SecurityContextHolder.getContext().getAuthentication();
        String name = u.getName();
        User user = users.findOneByName(name);
        if (user != null) {
            return new ResponseEntity<>(user, HttpStatus.OK);
        }
        return new ResponseEntity<Object>("Invalid token.", HttpStatus.BAD_REQUEST);
    }

    // get user
    @RequestMapping(path = "/users/{userId}", method = RequestMethod.GET)
    public ResponseEntity<?> getUser(@PathVariable Integer userId) {
        User user = users.findOne(userId);
        if (user != null) {
            return new ResponseEntity<>(user, HttpStatus.OK);
        }
        return new ResponseEntity<>("Unable to find user", HttpStatus.BAD_REQUEST);
    }

    // add a new house
    @RequestMapping(path = "/users/{userId}/houses", method = RequestMethod.POST)
    public ResponseEntity<?> addHouse(@PathVariable Integer userId,
                                   @RequestBody Map<String, String> json) {
        String houseName = json.get("houseName");

        User user = users.findOne(userId);
        if (user != null) {
            House house = new House(houseName);
            if (user.getHouses().size() == 0) {
                house.setDefaultHouse(true);
            }
            user.addHouse(house);
            users.save(user);
            return new ResponseEntity<>(house, HttpStatus.OK);
        } else {
            return new ResponseEntity<>("Unable to find user", HttpStatus.BAD_REQUEST);
        }
    }

    // get a user's houses
    @RequestMapping(path = "/users/{userId}/houses", method = RequestMethod.GET)
    public ResponseEntity<?> getHouses(@PathVariable Integer userId) {
        User user = users.findOne(userId);
        if (user != null) {
            return new ResponseEntity<>(user.getHouses(), HttpStatus.OK);
        } else {
            return new ResponseEntity<>("No houses found by that user.", HttpStatus.BAD_REQUEST);
        }
    }

    // get a user's house
    @RequestMapping(path = "/users/{userId}houses/{houseId}", method = RequestMethod.GET)
    public ResponseEntity<?> getHouse(@PathVariable Integer userId,
                                      @PathVariable Integer houseId) {
        User user = users.findOne(userId);
        String errorMsg;
        if (user != null) {
            House house = user.getHouses().stream().filter(h -> h.getId() == houseId).findFirst().orElse(null);
            if (house != null) {
                return new ResponseEntity<>(house, HttpStatus.OK);
            } else {
                errorMsg = "Unable to find house by that id.";
            }
        } else {
            errorMsg = "Unable to find user by that id.";
        }
        return new ResponseEntity<>(errorMsg, HttpStatus.BAD_REQUEST);
    }

    // remove a user's house
    @RequestMapping(path = "/users/{userId}/houses/{houseId}", method = RequestMethod.DELETE)
    public void deleteHouse(@PathVariable Integer userId,
                            @PathVariable Integer houseId) {
        User user = users.findOne(userId);
        if (user != null) {
            user.getHouses().removeIf(house -> house.getId() == houseId);
            users.save(user);
        }
    }

    // get items from a user's house Todo
    @RequestMapping(path = "/users/{userId}/houses/{houseId}/items", method = RequestMethod.GET)
    public ResponseEntity<?> getItems(@PathVariable Integer userId,
                                      @PathVariable Integer houseId) {
        List<HouseHoldItem> houseItems = houseHoldItems.findByHouseId(houseId);
        if (houseItems != null) {
            return new ResponseEntity<>(houseItems, HttpStatus.OK);
        } else {
            return new ResponseEntity<>("Unable to find items for that house.", HttpStatus.BAD_REQUEST);
        }
    }

    // add an item to a house
    @RequestMapping(path = "/users/{userId}/houses/{houseId}/items", method = RequestMethod.POST)
    public void addItem(@PathVariable Integer userId,
                        @PathVariable Integer houseId,
                        @RequestBody Map<String, String> json) {
        String itemName = json.get("itemName");
        HouseHoldItem hhItem = new HouseHoldItem(houseId, new Item(itemName));
        houseHoldItems.save(hhItem);
    }

    // remove an item from a house
    @RequestMapping(path = "/users/{userId}/houses/{houseId}/items/{itemId}", method = RequestMethod.DELETE)
    public void deleteItem(@PathVariable Integer userId,
                           @PathVariable Integer houseId,
                           @PathVariable Integer itemId) {
        houseHoldItems.deleteByHouseIdAndItem_Id(houseId, itemId);
    }

    // Search Amazon Product API
    @RequestMapping(path = "/items/{category}/{keywords}/{page}", method = RequestMethod.GET)
    public ResponseEntity<?> searchItems(@PathVariable String keywords,
                                         @PathVariable String category,
                                         @PathVariable String page) {
        return SearchItem.lookUpItem(keywords, category, page);
    }
}
