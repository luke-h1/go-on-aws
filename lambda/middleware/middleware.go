package middleware

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/golang-jwt/jwt/v5"
)

// extract request headers, claims & validate

func ValidateJWTMIddleware(next func(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error)) func(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	return func(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
		
		// extract headers
		tokenString := extractTokenFromHeaders(request.Headers);
		if tokenString == "" {
			return events.APIGatewayProxyResponse{
				StatusCode: http.StatusForbidden,
				Body: "Missing auth token",
			}, nil
		}

		// parse token for its claims
		claims, err := parseToken(tokenString);
		if err != nil {
			return events.APIGatewayProxyResponse{
				Body: "User unauthorized",
				StatusCode: http.StatusUnauthorized,
			}, nil
		}

		expires := int64(claims["expires"].(float64));

		// token expired
		if time.Now().Unix() > expires {
			return events.APIGatewayProxyResponse{
				Body: "Token expired",
				StatusCode: http.StatusUnauthorized,
			}, nil
		}

		return next(request)
	}
}

func parseToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		secret := "secretcat";
		return []byte(secret), nil;
	})

	if err != nil {
		return nil, fmt.Errorf("unauthorized")
	}

	if !token.Valid {
		return nil, fmt.Errorf("Token is not valid - unauthorized")
	}

	claims, ok := token.Claims.(jwt.MapClaims);
	
	if !ok {
		return nil, fmt.Errorf("claims of unauthorized type")
	}
	return claims, nil
}

func extractTokenFromHeaders(headers map[string]string) string {
	authHeader, ok := headers["Authorization"];

	if !ok {
		return ""
	}
	splitToken := strings.Split(authHeader, "Bearer ");
	
	if len(splitToken) != 2 {
		return ""
	}
	return splitToken[1];
}