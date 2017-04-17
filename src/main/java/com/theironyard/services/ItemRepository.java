package com.theironyard.services;

import com.theironyard.entities.Item;
import org.springframework.data.repository.CrudRepository;

public interface ItemRepository extends CrudRepository<Item, Integer> {}
