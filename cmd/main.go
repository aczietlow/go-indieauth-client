package main

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go-indieauth-client/pkg/indieAuth"
	"html/template"
	"io"
	"log"
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
	id     string
	client indieAuth.Config
}

func newUser(id string) (User, error) {
	indieAuthClient, err := indieAuth.New(id)
	if err != nil {
		return User{}, err
	}

	return User{
		id,
		indieAuthClient,
	}, nil
}

type Progress struct {
	Step string
}

func newProgress() Progress {
	return Progress{
		Step: fmt.Sprintf("\nstep 1: Prompt User for ID\n"),
	}
}

type Data struct {
	Form        FormData
	Progress    Progress
	RedirectURL string
}

func newData() Data {
	return Data{
		Form:     newFormData(),
		Progress: newProgress(),
	}
}

func main() {

	e := echo.New()
	e.Use(middleware.Logger())
	e.Static("/css", "web/css")
	e.Static("/assets", "web/assets")
	clientUsers := make(Users)

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

		indieAuthClientUser, err := newUser(website)

		if err != nil {
			formData.Errors["url"] = fmt.Sprintf("Error when trying to parse the url: %v", err)
			return c.Render(422, "form", formData)
		}
		indieAuthClient := indieAuthClientUser.client

		// Just save everything in memory.
		clientUsers[indieAuthClient.Identifier.ProfileURL] = indieAuthClientUser
		log.Printf("\n\n%v\n\n", indieAuthClient.Identifier.ProfileURL)

		// TODO: fix this later. We can't render form and json in the same callback.
		c.Render(200, "form", formData)

		data.Progress.Step += fmt.Sprintf("\tUser ID (Canonicalized): %v\n", indieAuthClient.Identifier.ProfileURL)
		data.Progress.Step += fmt.Sprintf("Step 2: Discover Auth Server Endpoints\n\tToken Endpoint:%v\n\tAuthorization Endpoint:%v\n", indieAuthClient.Endpoint.TokenURL, indieAuthClient.Endpoint.AuthURL)

		redirectURL := indieAuthClient.GetAuthorizationRequestURL()
		log.Println(redirectURL)
		data.RedirectURL = redirectURL

		data.Progress.Step += fmt.Sprintf("Step 3: Build Authorization Request\n\tRequest URL - %v\n", redirectURL)

		c.Render(200, "url", data.RedirectURL)

		return c.Render(200, "progress", data.Progress)
	})

	e.GET("/redirect", func(c echo.Context) error {
		// @TODO should the website client be the one to pick these out and pass them? or should it just send all Params back as url.Value `c.QueryParams()`
		code := c.QueryParam("code")
		state := c.QueryParam("state")
		me := c.QueryParam("me")
		// Apparently this is optional, or indieauth.com doesn't implement it.
		issuer := c.QueryParam("iss")

		formData := newFormData()
		id, err := url.QueryUnescape(me)
		if err != nil {
			// @TODO this for sure isn't the correct venue for this.
			formData.Errors["url"] = fmt.Sprintf("Error when unescaping the me value received: %v", err)
			return c.Render(422, "form", formData)
		}

		formData.Values["url"] = id
		u, ok := clientUsers[id]

		if !ok {
			formData.Errors["url"] = fmt.Sprintf("No user for id: %v was found registered", id)
			return c.Render(422, "form", formData)
		}

		token, err := u.client.TokenExchange(state, code, issuer)
		if err != nil {
			formData.Errors["url"] = fmt.Sprintf("Error when attempting to exchange the token: %v", err.Error())
			return c.Render(422, "form", formData)
		}

		data.Progress.Step += fmt.Sprintf("Step 4: Exchanged Auth code for Bearer Token\n\tToken:%v\n", token)

		return c.Render(200, "index", data)
	})

	e.Logger.Fatal(e.Start(":9002"))
}
