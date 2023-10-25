package controllers

import (
	"context"
	"ecommerce/internal/database"
	"ecommerce/internal/models"
	"ecommerce/internal/tokens"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.UserData(database.Client, "users")
var productCollection *mongo.Collection = database.ProductData(database.Client, "products")
var validate = validator.New()

func SignUp() gin.HandlerFunc{
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		if err := c.BindJSON(&user); err != nil{
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		validationErr := validate.Struct(user)
		if validationErr != nil{
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr})
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email":user.Email})
		if err != nil{
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error":err})
			return
		}
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "user already exists"})
		}
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone":user.Phone})
		if err != nil{
			log.Panic(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error":err})
			return
		}
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "this phone number already used"})
		}
		password := HashPassword(*user.Password)
		user.Password = &password
		user.Created_At, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_At, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.ID = primitive.NewObjectID()
		user.User_ID = user.ID.Hex()
		token, refreshToken, _ := tokens.TokenGenerator(*user.Email, *user.First_Name, *user.Last_Name, user.User_ID)
		user.Token = &token
		user.Refresh_Token = &refreshToken
		user.UserCart = make([]models.ProductUser, 0)
		user.Address_Details = make([]models.Address, 0)
		user.Order_Status = make([]models.Order, 0)
		_, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error":"the user did not get created"})
			return
		}
		c.JSON(http.StatusCreated, "succesfully signed in!")
	}
}

func Login() gin.HandlerFunc{
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		var foundUser models.User
		if err := c.BindJSON(&user); err != nil{
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email":user.Email}).Decode(&foundUser)
		if err != nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error": "login or password incorrect"})
			return
		}
		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			fmt.Println(msg)
			return
		}
		token, refreshToken, _ := tokens.TokenGenerator(*foundUser.Email, *foundUser.First_Name, *foundUser.Last_Name, foundUser.User_ID)

		tokens.UpdateAllTokens(token, refreshToken, foundUser.User_ID)
		c.JSON(http.StatusFound, foundUser)
	}
}

func ProductViewAdmin() gin.HandlerFunc{
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		var products models.Product
		if err := c.BindJSON(&products); err != nil{
			c.JSON(http.StatusBadRequest, gin.H{"error":err.Error()})
			return
		}
		products.Product_ID = primitive.NewObjectID()
		_, insertErr := productCollection.InsertOne(ctx, products)
		if insertErr != nil{
			c.JSON(http.StatusInternalServerError, gin.H{"error":"error while inserting"})
			return
		}
		c.JSON(http.StatusOK, "succesfully added")
	}
}

func HashPassword(password string) string{
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil{
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword, providedPassword string) (bool, string){
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	valid := true
	msg:=""
	if err != nil{
		msg = "login or password is incorrect"
		valid = false
	}
	return valid, msg
}

func SearchProduct() gin.HandlerFunc{
	return func(c *gin.Context) {
		var productList []models.Product
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		cursor, err := productCollection.Find(ctx, bson.D{{}})
		
		if err != nil{
			c.IndentedJSON(http.StatusInternalServerError, "something went wrong")
			return
		}
		defer cursor.Close(ctx)
		err = cursor.All(ctx, &productList)
		if err != nil{
			log.Println(err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}
		if err := cursor.Err(); err != nil{
			log.Println(err)
			c.IndentedJSON(400, "invalid")
			return
		}
		c.IndentedJSON(200, productList)
	}

}

func SearchProductByQuery() gin.HandlerFunc{
	return func(c *gin.Context) {
		var searchProducts []models.Product
		queryParam := c.Query("name")
		
		if queryParam == ""{
			log.Println("query is empty")
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusNotFound, gin.H{"error": "invalid search index"})
			c.Abort()
			return
		}

		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		searchQueryDb, err := productCollection.Find(ctx, bson.M{"product_name": bson.M{"$regex":queryParam}})
		if err != nil{
			c.IndentedJSON(404, "something went wrong while fetching data")
			return
		}
		defer searchQueryDb.Close(ctx)

		err = searchQueryDb.All(ctx, &searchProducts)
		if err != nil{
			log.Println(err)
			c.IndentedJSON(400, "invalid")
			return
		}

		if err := searchQueryDb.Err(); err != nil{
			log.Println(err)
			c.IndentedJSON(400, "invalid request")
			return
		}

		c.IndentedJSON(200, searchProducts)
	}
}