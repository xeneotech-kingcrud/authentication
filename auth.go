package authentication

import(
	"time"
	"net/http"
	"strings"
	
	"github.com/dgrijalva/jwt-go"
)
var jwtKey = []byte("secret")
func generateJWT(delay int64)(string, error){
	expirationTime := time.Now().Add(time.Duration(delay)*time.Second)
	claims := &jwt.StandardClaims{
		ExpiresAt: expirationTime.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	return tokenString, err
}

func loginHandler(w http.ResponseWriter,r *http.Request){
	tokenString, err := generateJWT(3600)
	if err != nil{
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
	return
	}
	w.Write([]byte(tokenString))
}

func jwtMiddleware(next http.Handler) http.Handler{
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
		const bearerPrefix = "Bearer"
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, bearerPrefix){
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		tokenString := authHeader[len(bearerPrefix):]
		claims := &jwt.StandardClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token)(interface{}, error){
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
