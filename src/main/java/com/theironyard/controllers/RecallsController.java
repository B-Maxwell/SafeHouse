package com.theironyard.controllers;

import com.theironyard.api.RecallAPI;
import com.theironyard.entities.Item;
import com.theironyard.entities.Items;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Controller
@RequestMapping("/recalls")
@CrossOrigin
public class RecallsController {

    @Autowired
    private Items items;

    // Get recall for an item
    @RequestMapping(path = "/{itemId}", method = RequestMethod.GET)
    public ResponseEntity<?> searchRecallByItemId(@PathVariable Integer itemId) {
        Item item = items.findItemById(itemId);
        return new ResponseEntity<>(RecallAPI.checkRecall(item), HttpStatus.OK);
    }

    @RequestMapping(method = RequestMethod.GET)
    public ResponseEntity<?> searchRecallByItemInfo(@RequestParam String title, @RequestParam String brand, @RequestParam String model) {
        Item item = new Item();
        item.setTitle(title);
        item.setBrand(brand);
        item.setModel(model);
        return new ResponseEntity<>(RecallAPI.checkRecall(item), HttpStatus.OK);
    }
}
