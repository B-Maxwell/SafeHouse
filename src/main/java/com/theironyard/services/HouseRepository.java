package com.theironyard.services;

import com.theironyard.entities.House;
import org.springframework.data.repository.CrudRepository;

public interface HouseRepository extends CrudRepository<House, Integer> {
}
