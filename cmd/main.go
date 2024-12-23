package main

import (
	"fmt"
	"log"
	"mobilehub-auth/pkg/config"
	"mobilehub-auth/pkg/db"
	"mobilehub-auth/pkg/pb"
	"mobilehub-auth/pkg/services"
	"net"

	"google.golang.org/grpc"
)

func main() {
	c, err := config.LoadConfig()

	if err != nil {
		log.Fatalln("Failed at config", err)
	}

	h := db.Init(c.DBUrl)

	// jwt := utils.JwtWrapper{
	// 	SecretKey:       c.JWTSecretKey,
	// 	Issuer:          "go-grpc-auth-svc",
	// 	ExpirationHours: 24 * 365,
	// }

	lis, err := net.Listen("tcp", c.Port)

	if err != nil {
		log.Fatalln("Failed to listing:", err)
	}

	fmt.Println("Auth Svc on", c.Port)

	s := services.AuthServiceServer{
		H: h,
	}

	grpcServer := grpc.NewServer()

	pb.RegisterAuthServiceServer(grpcServer, &s)

	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalln("Failed to serve:", err)
	}
}
