package main

import (
	"fmt"
	"os"

	"github.com/acheong08/OpenAIAuth/auth"
)

func main() {
	auth := auth.NewAuthenticator(os.Getenv("OPENAI_EMAIL"), os.Getenv("OPENAI_PUID"), os.Getenv("OPENAI_PASSWORD"), os.Getenv("PROXY"))
	err := auth.Begin()
	if err.Error != nil {
		fmt.Println(err.Error)
		return
	}
	token, err := auth.GetAccessToken()
	if err.Error != nil {
		fmt.Println(err.Error)
		return
	}
	fmt.Println(token)
}
