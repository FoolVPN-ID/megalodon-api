package api

import (
	TH "github.com/FoolVPN-ID/tool/api"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func StartApi() {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.String(200, "hello from gin!")
	})

	// Middlewares
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST"},
		AllowHeaders:     []string{"Origin"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Sub
	r.GET("/sub", handleGetSubApi)

	// Users
	r.GET("/user/:apiToken/:id", handleGetUserApi)

	// regioncheck
	r.GET("/regioncheck", TH.HandleGetRegionCheck)

	// convert
	r.POST("/convert", TH.HandlePostConvert)

	// udprelay
	r.POST("/udprelay", TH.HandlePostUdpRelay)

	// Listen on port 8080 by default
	r.Run()
}
