package models

import "gorm.io/gorm"

type User struct {
	gorm.Model
	//ID        int64  `gorm:"primary key" json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	Phone     uint64 `json:"phone"`
}

type Admin struct {
	gorm.Model
	//ID       int64  `gorm:"primary key" json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}
