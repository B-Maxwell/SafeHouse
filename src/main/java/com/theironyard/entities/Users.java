package com.theironyard.entities;

import com.theironyard.services.HouseRepository;
import com.theironyard.services.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

@Service
public final class Users {

    private UserRepository userRepo;
    private HouseRepository houseRepo;
    private final List<String> COLORS = Arrays.asList("red", "blue", "green", "yellow", "purple",
                                                        "pink", "grey", "cyan", "orange");

    @Autowired
    private Items items;

    @Autowired
    public Users(UserRepository userRepo, HouseRepository houseRepo) {
        this.userRepo = userRepo;
        this.houseRepo = houseRepo;
    }

    public User save(User user) throws DataIntegrityViolationException {
        return userRepo.save(user);
    }

    public User findByName(String name) {
        return userRepo.findByName(name);
    }

    public User findOne(Integer userId) {
        return userRepo.findOne(userId);
    }

    public Boolean deleteHouse(Integer userId, Integer houseId) {
        User user = userRepo.findOne(userId);
        if (user != null) {
            House house = user.getHouses().stream().filter(h -> h.getId() == houseId).findFirst().orElse(null);
            if (house != null) {
                user.getHouses().remove(house);
                if (house.getDefaultHouse() && user.getHouses().size() >= 1) {
                    user.getHouses().get(0).setDefaultHouse(true);
                }
                userRepo.save(user);
                houseRepo.delete(houseId);
                items.deleteByHouseId(houseId); // remove the household items that were in the house
                return true;
            }
        }
        return false;
    }

    public void updateHouseName(Integer userId, Integer houseId, String newName) {
        User user = userRepo.findOne(userId);
        if (user != null && user.getHouses().size() > 0) {
            House house = user.getHouses().stream().filter(h -> h.getId() == houseId).findFirst().orElse(null);
            if (house != null && !house.getName().equals(newName)) {
                house.setName(newName);
                userRepo.save(user);
            }
        }
    }

    public Response addHouse(Integer userId, String houseName) {
        User user = userRepo.findOne(userId);
        if (user != null) {
            List<String> takenColors = user
                    .getHouses()
                    .stream()
                    .map(House::getColor)
                    .collect(Collectors.toList());

            List<String> availableColors = COLORS
                                        .stream()
                                        .filter(c -> ! takenColors.contains(c))
                                        .collect(Collectors.toList());

            String color;
            if (availableColors.size() > 0) {
                color = availableColors.get(new Random().nextInt(availableColors.size()));
            } else {
                color = COLORS.get(new Random().nextInt(COLORS.size()));
            }

            House house = new House(houseName, color);
            if (user.getHouses().size() == 0) {
                house.setDefaultHouse(true);
            }
            user.addHouse(house);
            userRepo.save(user);
            return new Response(house);
        } else {
            return new Response("Unable to find user by that id.", HttpStatus.BAD_REQUEST);
        }
    }

    public Response deleteAccount(Integer userId) {
        User user = userRepo.findOne(userId);
        if (user != null) {
            List<Integer> houseIds = user
                    .getHouses()
                    .stream()
                    .map(House::getId)
                    .collect(Collectors.toList());
            houseIds.forEach(id -> items.deleteByHouseId(id));
            userRepo.delete(user);
            return new Response("Success");
        } else {
            return new Response("Cannot find a user by that id.", HttpStatus.BAD_REQUEST);
        }
    }

    public House findHouse(Integer userId, Integer houseId) {
        User user = userRepo.findOne(userId);
        if (user != null) {
            return user
                    .getHouses()
                    .stream()
                    .filter(house -> house.getId() == houseId)
                    .findFirst()
                    .orElse(null);
        } else {
            return null;
        }
    }

}
