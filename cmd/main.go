package main

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go-indieauth-client/pkg/indieAuth"
	"html/template"
	"io"
	"log"
	"os"
)

type Templates struct {
	templates *template.Template
}

func (t *Templates) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func newTemplate() *Templates {
	return &Templates{
		templates: template.Must(template.ParseGlob("web/views/*.html")),
	}
}

type FormData struct {
	Values map[string]string
	Errors map[string]string
}

func newFormData() FormData {
	return FormData{
		Values: make(map[string]string),
		Errors: make(map[string]string),
	}
}

type Users = map[string]User

type User struct {
	// Should be a URL type?
	id string
}

func newUser(id string) User {
	return User{
		id,
	}
}

type Progress struct {
	Step string
}

func newProgress() Progress {
	return Progress{
		Step: "step 1: Prompt User for ID\n",
	}
}

type Data struct {
	Form     FormData
	Users    Users
	Progress Progress
}

func newData() Data {
	return Data{
		Form:     newFormData(),
		Progress: newProgress(),
	}
}

type RedirectResponse struct {
	URL string `json:"url"`
}

func main() {

	e := echo.New()
	e.Use(middleware.Logger())
	e.Static("/css", "web/css")

	// Inline debugging.
	//log.Println()

	data := newData()
	e.Renderer = newTemplate()

	e.GET("/", func(c echo.Context) error {
		return c.Render(200, "index", data)
	})

	e.POST("/auth", func(c echo.Context) error {
		website := c.FormValue("url")
		formData := newFormData()
		formData.Values["url"] = website

		indieAuthClient, err := indieAuth.New(website)
		log.Println(os.Getwd())

		if err != nil {
			formData.Errors["url"] = fmt.Sprintf("Error when trying to parse the url: %v", err)
			return c.Render(422, "form", formData)
		}

		// TODO: fix this later. We can't render form and json in the same callback.
		c.Render(200, "form", formData)

		data.Progress.Step += fmt.Sprintf("Step 2:\nToken Endpoint:%v\nAuthorization Endpoint:%v", indieAuthClient.Endpoint.TokenURL, indieAuthClient.Endpoint.AuthURL)

		redirectURL := indieAuthClient.GetAuthorizationRequestURL()

		log.Printf("client_id:%v\n url:%v\n", indieAuthClient.ClientID, indieAuthClient.RedirectURL)
		log.Printf("id:%v\n", indieAuthClient.Identifier)
		//http.Redirect(w, r, redirectURL, 301)
		log.Println("should redirect here.")

		//response := RedirectResponse{
		//	URL: redirectURL,
		//}

		log.Println(redirectURL)
		// @TODO: Find a way to do this that doesn't require JSON.
		//return c.JSON(http.StatusOK, response)

		return c.Render(200, "progress", data.Progress)
	})

	e.Logger.Fatal(e.Start(":9002"))
}
