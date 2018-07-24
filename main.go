package main

import (
	"context"
	"encoding/json"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

type User struct {
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type AuthTokens struct {
	AccessToken  *string `json:"access_token"`
	IdToken      *string `json:"id_token"`
	RefreshToken *string `json:"refresh_token"`
	ExpiresIn    *int64  `json:"expires_in"`
}

func HandleRequest(ctx context.Context, event events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	sess, err := session.NewSession()
	if err != nil {
		return events.APIGatewayProxyResponse{Body: err.Error()}, nil
	}
	var user User
	err = json.Unmarshal([]byte(event.Body), &user)
	if err != nil {
		return events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: 400}, nil
	}
	cog := cognitoidentityprovider.New(sess)
	params := user.generateParams()
	resp, err := cog.AdminInitiateAuth(params)
	if err != nil {
		return events.APIGatewayProxyResponse{Body: err.Error(), StatusCode: 400}, nil
	}
	var tokens AuthTokens
	tokens.AccessToken = resp.AuthenticationResult.AccessToken
	tokens.RefreshToken = resp.AuthenticationResult.RefreshToken
	tokens.IdToken = resp.AuthenticationResult.IdToken
	tokens.ExpiresIn = resp.AuthenticationResult.ExpiresIn
	data, err := json.Marshal(tokens)
	return events.APIGatewayProxyResponse{
		Body:       string(data),
		StatusCode: 200,
	}, nil
}

// Generate params either for username/password login or refresh token
func (user *User) generateParams() *cognitoidentityprovider.AdminInitiateAuthInput {
	if user.Username != "" && user.Password != "" {
		params := &cognitoidentityprovider.AdminInitiateAuthInput{
			AuthFlow: aws.String("ADMIN_NO_SRP_AUTH"),
			AuthParameters: map[string]*string{
				"USERNAME": aws.String(user.Username),
				"PASSWORD": aws.String(user.Password),
			},
			ClientId:   aws.String(os.Getenv("CLIENT_ID")),
			UserPoolId: aws.String(os.Getenv("POOL_ID")),
		}
		return params
	} else if user.RefreshToken != "" {
		params := &cognitoidentityprovider.AdminInitiateAuthInput{
			AuthFlow: aws.String("REFRESH_TOKEN_AUTH"),
			AuthParameters: map[string]*string{
				"REFRESH_TOKEN": aws.String(user.RefreshToken),
			},
			ClientId:   aws.String(os.Getenv("CLIENT_ID")),
			UserPoolId: aws.String(os.Getenv("POOL_ID")),
		}
		return params
	}

	return nil
}

//Entrypoint lambda to run code
func main() {
	switch os.Getenv("PLATFORM") {
	case "lambda":
		lambda.Start(HandleRequest)
	default:
		log.Println("no platform defined")
	}
}
