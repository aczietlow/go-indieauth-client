package main

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go-indieauth-client/pkg/indieAuthClient"
	"html/template"
	"io"
	"net/url"
)

type Templates struct {
	templates *template.Template
}

func (t *Templates) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func newTemplate() *Templates {
	return &Templates{
		templates: template.Must(template.ParseGlob("website/views/*.html")),
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
		Step: "step 1",
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

func (u User) IsUrl(id string) bool {
	website, err := url.Parse(id)
	if err != nil {
		return false
	}
	if website.Scheme == "" {
		//if website.Scheme == "" || website.Host == "" {
		return false
	}
	return true
}

func main() {
	e := echo.New()
	e.Use(middleware.Logger())
	e.Static("/css", "website/css")

	data := newData()
	e.Renderer = newTemplate()

	e.GET("/", func(c echo.Context) error {
		return c.Render(200, "index", data)
	})

	e.POST("/auth", func(c echo.Context) error {
		website := c.FormValue("url")
		formData := newFormData()
		formData.Values["url"] = website
		user := newUser(website)

		if !user.IsUrl(website) {
			formData.Errors["url"] = "Not a valid domain."
			return c.Render(422, "form", formData)
		}

		c.Render(200, "form", formData)

		AuthServerURL := indieAuthClient.DiscoveryAuthServer(website)

		if AuthServerURL != "" {
			formData.Errors["url"] = fmt.Sprintf("Couldn't find <link rel=authorization_endpoint> at %s", website)
			return c.Render(422, "form", formData)
		}

		AuthServer := indieAuthClient.NewServer(AuthServerURL)
		AuthServer.Identity = website

		data.Progress.Step = fmt.Sprintf("Step 2\nToken Endpoint:%v\nAuthorization Endpoint:%v", AuthServer.TokenEndpoint, AuthServer.AuthorizationEndpoint)
		return c.Render(200, "progress", data.Progress)
	})

	e.Logger.Fatal(e.Start(":9002"))
}
