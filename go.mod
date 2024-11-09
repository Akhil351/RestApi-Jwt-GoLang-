module project

//  go get github.com/golang-jwt/jwt/v5 (for jwt token)
// go get github.com/google/uuid
// go get golang.org/x/crypto/bcrypt (for password)
// go get github.com/justinas/alice
// go get -u github.com/gorilla/mux
// go get -u gorm.io/gorm (helps us to interact struct with database)
// go get -u gorm.io/driver/postgres ( help gorm to connect to the database)
// go get github.com/joho/godotenv
// go install github.com/air-verse/air@latest
// air init and air

go 1.23.2

require (
	github.com/gorilla/mux v1.8.1
	github.com/joho/godotenv v1.5.1
	github.com/justinas/alice v1.2.0
	gorm.io/driver/postgres v1.5.9
	gorm.io/gorm v1.25.12
)

require (
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.7.1 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	golang.org/x/crypto v0.29.0 // indirect
	golang.org/x/sync v0.9.0 // indirect
	golang.org/x/text v0.20.0 // indirect
)
