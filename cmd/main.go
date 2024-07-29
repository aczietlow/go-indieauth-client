package main

import (
	"fmt"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"go-indieauth-client/pkg/indieAuth"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"path/filepath"
)

type Templates struct {
	templates *template.Template
}

func (t *Templates) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func newTemplate() *Templates {
	// @TODO During boot, find all directories with templates.
	templateDirs := []string{
		"web/views",
		"web/views/partials",
	}

	templates := template.New("")
	for _, dir := range templateDirs {
		// Using filepath.Glob to get all template files
		files, err := filepath.Glob(filepath.Join(dir, "*.html"))
		if err != nil {
			panic(err)
		}
		for _, file := range files {
			log.Printf("Adding %v to temaplte path", file)
			// Parse each template file and add to the template set
			_, err = templates.ParseFiles(file)
			if err != nil {
				panic(err)
			}
		}
	}

	return &Templates{
		templates: templates,
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
	Info  string
	Step  string
	Query string
}

func newProgress() Progress {
	return Progress{
		Info: fmt.Sprintf("\nstep 1: Prompt User for ID\n"),
		Step: "discovery",
	}
}

type Data struct {
	Form          FormData
	Progress      Progress
	RedirectURL   string
	Authenticated bool
}

func newData() Data {
	return Data{
		Form:          newFormData(),
		Progress:      newProgress(),
		Authenticated: false,
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

		formData.Values["authorization_endpoint"] = indieAuthClient.Endpoint.AuthURL
		formData.Values["token_endpoint"] = indieAuthClient.Endpoint.TokenURL

		c.Render(200, "login-form", formData)

		data.Progress.Info += fmt.Sprintf("\tUser ID (Canonicalized): %v\n", indieAuthClient.Identifier.ProfileURL)
		data.Progress.Info += fmt.Sprintf("Info 2: Discover Auth Server Endpoints\n\tToken Endpoint:%v\n\tAuthorization Endpoint:%v\n", indieAuthClient.Endpoint.TokenURL, indieAuthClient.Endpoint.AuthURL)

		redirectURL := indieAuthClient.GetAuthorizationRequestURL()
		log.Println(redirectURL)
		data.RedirectURL = redirectURL

		data.Progress.Info += fmt.Sprintf("Info 3: Build Authorization Request\n\tRequest URL - %v\n", redirectURL)
		data.Progress.Step = "authorization-request"

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

		formData.Values["authorization_endpoint"] = u.client.Endpoint.AuthURL
		formData.Values["token_endpoint"] = u.client.Endpoint.TokenURL

		data.Progress.Info += fmt.Sprintf("Info 4: Exchanged Auth code for Bearer Token\n\tToken:%v\n", token)
		data.Form = formData
		data.Progress.Step = "redeeming-authorization-code"

		// Write a cookie
		cookie := new(http.Cookie)
		cookie.Name = "indieAuthClient"
		cookie.Value = token
		//cookie.HttpOnly = true
		//cookie.Expires = time.Now().Add(24 * time.Hour)
		c.SetCookie(cookie)
		return c.Render(200, "index", data)
	})

	e.GET("/secrets", func(c echo.Context) error {
		// @TODO pull the access token from a cookie in the user browser instead of from an in memory object.
		cookie, err := c.Cookie("indieAuthClient")

		if err != nil {
			// @TODO 200's are NOT how access denied is handled..... Drupal
			log.Printf("Encountered an error %v", err.Error())
			return c.Render(200, "secrets", data)
		}
		token := cookie.Value
		log.Printf("User token is %v", token)

		data.Authenticated = true

		// @TODO Clean the "data" structure up to be more sane
		return c.Render(200, "secrets", data)
	})

	// @TODO Remove poor mans data wipe.
	e.GET("/reset", func(c echo.Context) error {
		clientUsers = make(Users)
		data = newData()

		return c.Render(200, "index", data)
	})

	e.Logger.Fatal(e.Start(":9002"))
}
