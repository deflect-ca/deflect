// Copyright (c) 2020, eQualit.ie inc.
// All rights reserved.
//
// This source code is licensed under the BSD-style license found in the
// LICENSE file in the root directory of this source tree.

package main

import (
    "fmt"
    "net/http"
    "github.com/gin-gonic/gin"
    "strings"
)

func main() {
    r := gin.Default()
        r.NoRoute(func(c *gin.Context) {
        // c.Header("Cache-Control", "no-cache")
        c.Header("Cache-Control", "public,max-age=30")
        c.JSON(200, gin.H{
                    "you-requested": c.Request.URL.Path,
                    "message": strings.Repeat("hello world", 3),
		    "request-headers": c.Request.Header,
        })
    })

    r.GET("/GET", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "method": "GET",
            "param": c.DefaultQuery("param", "default"),
        })
    })

    r.HEAD("/HEAD", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "method": "HEAD",
            "param": c.DefaultQuery("param", "default"),
        })
    })

    r.POST("/POST", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "method": "POST",
            "param": c.DefaultQuery("param", "default"),
            "form": c.PostForm("form"),
        })
    })

    r.POST("/POST_RAW", func(c *gin.Context) {
        raw, err := c.GetRawData()
        c.JSON(200, gin.H{
            "method": "POST",
            "param": c.DefaultQuery("param", "default"),
            "raw": raw,
            "err": err,
        })
    })

    r.OPTIONS("/OPTIONS", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "method": "OPTIONS",
            "param": c.DefaultQuery("param", "default"),
        })
    })

    r.PUT("/PUT", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "method": "PUT",
            "param": c.DefaultQuery("param", "default"),
            "form": c.PostForm("form"),
        })
    })

    r.PUT("/PUT_RAW", func(c *gin.Context) {
        raw, err := c.GetRawData()
        c.JSON(200, gin.H{
            "method": "PUT",
            "param": c.DefaultQuery("param", "default"),
            "raw": raw,
            "err": err,
        })
    })

    r.PATCH("/PATCH", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "method": "PATCH",
            "param": c.DefaultQuery("param", "default"),
            "form": c.PostForm("form"),
        })
    })

    r.PATCH("/PATCH_RAW", func(c *gin.Context) {
        raw, err := c.GetRawData()
        c.JSON(200, gin.H{
            "method": "PATCH",
            "param": c.DefaultQuery("param", "default"),
            "raw": raw,
            "err": err,
        })
    })

    r.DELETE("/DELETE", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "method": "DELETE",
            "param": c.DefaultQuery("param", "default"),
        })
    })

    // upload file
    // Set a lower memory limit for multipart forms (default is 32 MiB)
    r.MaxMultipartMemory = 8 << 20  // 8 MiB
    r.POST("/upload", func(c *gin.Context) {
        // single file
        file, err := c.FormFile("file")
        if err != nil {
            c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
            return
        }
        // Upload the file to specific dst.
        if err := c.SaveUploadedFile(file, "/opt/hello-world/upload.png"); err != nil {
            c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
            return
        }
        c.JSON(200, gin.H{
            "method": "POST",
            "param": c.DefaultQuery("param", "default"),
            "upload": file.Filename,
        })
    })

    r.Run() // listen and serve on 0.0.0.0:8080
}
