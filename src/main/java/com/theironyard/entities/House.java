package com.theironyard.entities;

import javax.persistence.*;

@Entity
@Table(name = "houses")
public class House {

    @Id
    @GeneratedValue
    private int id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private Boolean defaultHouse = false;

    public House(String name) {
        this.name = name;
    }

    public House() {}

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public Boolean getDefaultHouse() {
        return defaultHouse;
    }

    public void setDefaultHouse(Boolean defaultHouse) {
        this.defaultHouse = defaultHouse;
    }
}
