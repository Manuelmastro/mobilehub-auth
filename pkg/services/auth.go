package services

import (
	"context"
	"fmt"
	"net/http"

	"mobilehub-auth/pkg/db"
	"mobilehub-auth/pkg/models"
	"mobilehub-auth/pkg/pb"
	"mobilehub-auth/pkg/utils"

	"github.com/golang-jwt/jwt/v4"
)

type AuthServiceServer struct {
	pb.UnimplementedAuthServiceServer
	H db.Handler
}

type CustomClaims struct {
	Email string `json:"email"`
	Role  string `json:"role"`
	ID    uint   `json:"id"`
	jwt.StandardClaims
}

var jwtSecret = []byte("your-secret-key")

func (s *AuthServiceServer) Validate(ctx context.Context, req *pb.ValidateRequest) (*pb.ValidateResponse, error) {
	tokenString := req.Token

	// Parse and validate the token
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil || !token.Valid {
		return &pb.ValidateResponse{
			Status: http.StatusUnauthorized,
			Error:  "Invalid token",
		}, nil
	}

	claims, ok := token.Claims.(*CustomClaims)
	if !ok {
		return &pb.ValidateResponse{
			Status: http.StatusUnauthorized,
			Error:  "Invalid token claims",
		}, nil
	}
	fmt.Printf("Parsed Claims: Role=%s, ID=%d\n", claims.Role, claims.ID)
	fmt.Printf("Returning Response: Status=%d, UserId=%d, Role=%s\n", http.StatusOK, claims.ID, claims.Role)

	return &pb.ValidateResponse{
		Status: http.StatusOK,
		UserId: int64(claims.ID),
		Role:   claims.Role,
	}, nil

}

func (s *AuthServiceServer) UserSignup(ctx context.Context, req *pb.UserSignupRequest) (*pb.UserSignupResponse, error) {
	var user models.User

	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error == nil {
		return &pb.UserSignupResponse{
			Status: http.StatusConflict,
			Error:  "E-Mail already exists",
		}, nil
	}

	user.Email = req.Email
	user.Password = req.Password
	user.FirstName = req.Firstname
	user.LastName = req.Lastname
	user.Phone = req.Phone

	s.H.DB.Create(&user)

	return &pb.UserSignupResponse{
		Status: http.StatusCreated,
	}, nil
}

func (s *AuthServiceServer) AdminLogin(ctx context.Context, req *pb.AdminLoginRequest) (*pb.AdminLoginResponse, error) {
	var admin models.Admin

	// Check if the user exists in the database by email
	if result := s.H.DB.Where(&models.Admin{Email: req.Email}).First(&admin); result.Error != nil {
		return &pb.AdminLoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}

	// Directly compare the provided password with the stored password
	if req.Password != admin.Password {
		return &pb.AdminLoginResponse{
			Status: http.StatusUnauthorized,
			Error:  "Invalid credentials",
		}, nil
	}

	// Generate a JWT token for the user
	token, _ := utils.GenerateJWT("admin", admin.Email, uint(admin.ID))

	return &pb.AdminLoginResponse{
		Status: http.StatusOK,
		Token:  token,
	}, nil
}

func (s *AuthServiceServer) UserLogin(ctx context.Context, req *pb.UserLoginRequest) (*pb.UserLoginResponse, error) {
	var user models.User

	// Check if the user exists in the database by email
	if result := s.H.DB.Where(&models.User{Email: req.Email}).First(&user); result.Error != nil {
		return &pb.UserLoginResponse{
			Status: http.StatusNotFound,
			Error:  "User not found",
		}, nil
	}

	// Directly compare the provided password with the stored password
	if req.Password != user.Password {
		return &pb.UserLoginResponse{
			Status: http.StatusUnauthorized,
			Error:  "Invalid credentials",
		}, nil
	}

	// Generate a JWT token for the user
	token, _ := utils.GenerateJWT("user", user.Email, uint(user.ID))

	return &pb.UserLoginResponse{
		Status: http.StatusOK,
		Token:  token,
	}, nil
}
