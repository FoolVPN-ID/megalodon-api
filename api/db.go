package api

import (
	"strings"

	database "github.com/FoolVPN-ID/megalodon-api/modules/db"
	"github.com/FoolVPN-ID/megalodon-api/modules/db/kv"
	"github.com/gin-gonic/gin"
)

type dbExecForm struct {
	Query string `json:"query"`
}

func handlePostDBQuery(c *gin.Context) {
	// Validate api token
	apiToken := c.Param("apiToken")
	if apiToken == "" {
		c.String(403, "token invalid")
		return
	}

	kvClient := kv.MakeKVTableClient()
	validToken, err := kvClient.GetValueFromKVByKey("apiToken")
	if err != nil {
		c.String(500, err.Error())
		return
	} else if *validToken == "" {
		c.String(500, "token not set")
		return
	} else if *validToken != apiToken {
		c.String(403, "token invalid")
		return
	}

	var (
		dbExecQueryForm dbExecForm
		db              = database.MakeDatabase()
		dbClient        = db.GetClient()
	)

	if err := c.ShouldBind(&dbExecQueryForm); err != nil {
		c.String(403, err.Error())
		return
	}

	// Begin transaction
	dbTr, err := dbClient.Begin()
	if err != nil {
		c.String(500, err.Error())
		return
	}

	for _, query := range strings.Split(dbExecQueryForm.Query, ");") {
		if query != "" {
			if _, err = dbTr.Exec(query + ");"); err != nil {
				dbTr.Rollback()
				c.String(500, err.Error())
				return
			}
		}
	}

	// Execute transaction
	err = dbTr.Commit()
	if err != nil {
		dbTr.Rollback()
		c.String(500, err.Error())
	}
}
