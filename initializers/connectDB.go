package initializers

import (
	"log"
	"os"

	"github.com/ssss-tantalum/go-gin-jwt-rs-256/models"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

func ConnectDB(config *Config) {
	var err error
	// dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Tokyo", config.DBHost, config.DBUserName, config.DBUserPassword, config.DBName, config.DBPort)

	dsn := "host=postgres user=root password=password dbname=mydb port=5432 sslmode=disable TimeZone=Asia/Tokyo"
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to the Database! \n", err.Error())
		os.Exit(1)
	}

	DB.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
	DB.Logger = logger.Default.LogMode(logger.Info)

	log.Println("Running Migrations")
	err = DB.AutoMigrate(&models.User{})
	if err != nil {
		log.Fatal("Migration Failed:  \n", err.Error())
		os.Exit(1)
	}

	log.Println("🚀 Connected Successfully to the Database")
}
