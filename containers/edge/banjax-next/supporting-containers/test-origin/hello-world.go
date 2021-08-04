// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
	"github.com/gin-gonic/gin"
	"time"
)

func main() {
	r := gin.Default()
	r.GET("/hello", func(c *gin.Context) {
	    c.String(200, "hello!\n")
    })
	r.NoRoute(func(c *gin.Context) {
		// c.Header("Cache-Control", "no-cache")
		c.Header("Cache-Control", "public,max-age=30")
		c.String(404, "you requested %s at %s\n", c.Request.URL.Path, time.Now().UTC().Format("15:04:05"))
	})
	r.Run("0.0.0.0:8080")
}
