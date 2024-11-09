package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/justinas/alice"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type App struct {
	DB      *gorm.DB
	JWT_KEY string
}
type User struct {
	Id       string `gorm:"primary_key"`
	Name     string
	Email    string `gorm:"unique"`
	Password string
}
type Project struct {
	Id          string `gorm:"primary_key"`
	UserId      string
	Name        string
	Description string
	GitHubUrl   string
}
type ProjectDto struct {
	Id          string `json:"id"`
	UserId      string `json:"user_id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	GitHubUrl   string `json:"githuburl"`
}
type UserDto struct {
	Name     string `json:"name,omitempty"`
	Email    string `json:"email"`
	Password string `json:"password,omitempty"`
}
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Claims struct {
	UserId   string
	Name     string
	Email    string
	Password string
	jwt.RegisteredClaims
}

type Response struct {
	Status    string      `json:"status"`
	TimeStamp time.Time   `json:"time_stamp"`
	Data      interface{} `json:"data"`
	Error     interface{} `json:"error"`
}

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Err loading .env file")
	}
	connStr := os.Getenv("DATA_PSQL_URL")
	if len(connStr) == 0 {
		log.Fatalf("DATA_PSQL_URL environment variable is nit set")
	}
	DB, err := gorm.Open(postgres.Open(connStr), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}
	DB.AutoMigrate(&User{}, &Project{})
	app := &App{DB: DB, JWT_KEY: os.Getenv("JWT_SECRET_KEY")}
	log.Println("Starting server...")
	router := mux.NewRouter()
	log.Println("Setting up routes")
	router.Handle("/register", alice.New(loggingMiddleware).ThenFunc(app.register)).Methods("POST")
	router.Handle("/login", alice.New(loggingMiddleware).ThenFunc(app.login)).Methods("POST")
	chain := alice.New(loggingMiddleware, app.jwtMiddleware)
	router.Handle("/projects", chain.ThenFunc(app.createProject)).Methods("POST")
	router.Handle("/projects/{id}", chain.ThenFunc(app.updateProject)).Methods("PUT")
	router.Handle("/projects", chain.ThenFunc(app.getProjects)).Methods("GET")
	router.Handle("/projects/{id}", chain.ThenFunc(app.getProject)).Methods("GET")
	router.Handle("/projects/{id}", chain.ThenFunc(app.deleteProject)).Methods("DELETE")

	log.Println("Listening in port 8080")
	http.ListenAndServe("localhost:8080", router)

}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s %s\n", r.RemoteAddr, r.Method, r.URL)
		next.ServeHTTP(w, r)
	})
}

func (app *App) jwtMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			CreateResponse(w, errors.New("no token provided"), nil, http.StatusUnauthorized)
			return
		}
		jwtToken := strings.TrimPrefix(authHeader, "Bearer ")
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(jwtToken, claims, func(t *jwt.Token) (interface{}, error) {
			return []byte(app.JWT_KEY), nil
		})
		if err != nil {
			if err == jwt.ErrSignatureInvalid {
				CreateResponse(w, errors.New("invalid token signature"), nil, http.StatusUnauthorized)
				return
			}

			CreateResponse(w, errors.New("invalid token"), nil, http.StatusBadRequest)
			return
		}
		if !token.Valid {
			CreateResponse(w, errors.New("invalid token"), nil, http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), "claims", claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (app *App) generateToken(user User) (string, error) {
	expirationTime := time.Now().Add(time.Hour)
	claims := &Claims{
		UserId:   user.Id,
		Name:     user.Name,
		Email:    user.Email,
		Password: user.Password,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(app.JWT_KEY))
	if err != nil {
		return "", err
	}
	return tokenString, nil

}

// register
func (app *App) register(w http.ResponseWriter, r *http.Request) {
	var user UserDto
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	err = ValidateUserRequest(user)
	if err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	bcryptPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	Id := "u" + uuid.New().String()
	saveUser := User{
		Id:       Id,
		Name:     user.Name,
		Email:    user.Email,
		Password: string(bcryptPassword),
	}
	if err := app.DB.Save(&saveUser).Error; err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	CreateResponse(w, nil, "User Register SuccessFully", http.StatusOK)

}

// login

func (app *App) login(w http.ResponseWriter, r *http.Request) {
	var request LoginRequest
	err := json.NewDecoder(r.Body).Decode(&request)
	if err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	var user User
	if err := app.DB.Where("email=?", request.Email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			CreateResponse(w, err, nil, http.StatusUnauthorized)
			return
		}
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(request.Password))
	if err != nil {
		CreateResponse(w, err, nil, http.StatusUnauthorized)
		return
	}

	jwtToken, err := app.generateToken(user)
	if err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	CreateResponse(w, nil, jwtToken, http.StatusBadRequest)

}

// createProject

func (app *App) createProject(w http.ResponseWriter, r *http.Request) {
	var projectRequest ProjectDto
	err := json.NewDecoder(r.Body).Decode(&projectRequest)
	if err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	claims := r.Context().Value("claims").(*Claims)
	userId := claims.UserId
	project := Project{
		Id:          "p" + uuid.New().String(),
		Name:        projectRequest.Name,
		UserId:      userId,
		Description: projectRequest.Description,
		GitHubUrl:   projectRequest.GitHubUrl,
	}
	if err := app.DB.Save(&project).Error; err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	projectRequest.Id = project.Id
	projectRequest.UserId = project.UserId
	CreateResponse(w, nil, projectRequest, http.StatusOK)
}

// updateProject
func (app *App) updateProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	claims := r.Context().Value("claims").(*Claims)
	userId := claims.UserId
	var projectDto ProjectDto
	err := json.NewDecoder(r.Body).Decode(&projectDto)
	if err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	var project Project
	if err := app.DB.Where("id=?", id).First(&project).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			CreateResponse(w, errors.New("product not found"), nil, http.StatusNotFound)
			return
		}
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	if project.UserId != userId {
		CreateResponse(w, errors.New("you dont have permisson to update"), nil, http.StatusForbidden)
		return
	}
	updateProjectFields(&project, projectDto)
	if err := app.DB.Save(&project).Error; err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	fmt.Println(project)
	projectDto = ProjectDto{
		Id:          project.Id,
		Name:        project.Name,
		UserId:      project.UserId,
		Description: project.Description,
		GitHubUrl:   project.GitHubUrl,
	}
	CreateResponse(w, nil, projectDto, http.StatusOK)

}

// getProjects

func (app *App) getProjects(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value("claims").(*Claims)
	userId := claims.UserId
	var projects []Project
	if err := app.DB.Where("user_id=?", userId).Find(&projects).Error; err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	var projectsDto []ProjectDto
	for _, project := range projects {
		projectDto := ProjectDto{
			Id:          project.Id,
			Name:        project.Name,
			UserId:      project.UserId,
			Description: project.Description,
			GitHubUrl:   project.GitHubUrl,
		}
		projectsDto = append(projectsDto, projectDto)
	}
	CreateResponse(w, nil, projectsDto, http.StatusOK)

}

// getProject

func (app *App) getProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	claims := r.Context().Value("claims").(*Claims)
	userId := claims.UserId
	var project Project
	if err := app.DB.Where("id=? And user_id=?", id, userId).First(&project).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			CreateResponse(w, errors.New("product not found"), nil, http.StatusNotFound)
			return
		}
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	projectDto := ProjectDto{
		Id:          project.Id,
		Name:        project.Name,
		UserId:      project.UserId,
		Description: project.Description,
		GitHubUrl:   project.GitHubUrl,
	}
	CreateResponse(w, nil, projectDto, http.StatusOK)
}

// deleteProject

func (app *App) deleteProject(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	claims := r.Context().Value("claims").(*Claims)
	userId := claims.UserId
	var project Project
	if err := app.DB.Where("id=?", id).First(&project).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			CreateResponse(w, errors.New("product not found"), nil, http.StatusNotFound)
			return
		}
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	if project.UserId != userId {
		CreateResponse(w, errors.New("you dont have permisson to delete"), nil, http.StatusForbidden)
		return
	}
	if err := app.DB.Delete(&project).Error; err != nil {
		CreateResponse(w, err, nil, http.StatusBadRequest)
		return
	}
	CreateResponse(w, nil, "project deleted", http.StatusOK)

}

func CreateResponse(w http.ResponseWriter, err error, data interface{}, statusCode int) {
	w.Header().Set("Content-type", "application/json")
	errMsg := "no error"
	status := "Success"
	if err != nil {
		status = "Failed"
		errMsg = err.Error()
		w.WriteHeader(statusCode)
	}
	response := Response{
		Status:    status,
		TimeStamp: time.Now(),
		Data:      data,
		Error:     errMsg,
	}
	json.NewEncoder(w).Encode(response)

}

func ValidateUserRequest(user UserDto) error {
	if user.Email == "" {
		return errors.New("email field is required")
	}
	if user.Name == "" {
		return errors.New("name field is required")
	}
	if user.Password == "" {
		return errors.New("password field is required")
	}
	return nil
}

func updateProjectFields(product *Project, productDto ProjectDto) {
	if productDto.Name != "" {
		product.Name = productDto.Name
	}
	if productDto.Description != "" {
		product.Description = productDto.Description
	}
	if productDto.GitHubUrl != "" {
		product.GitHubUrl = productDto.GitHubUrl
	}
}
