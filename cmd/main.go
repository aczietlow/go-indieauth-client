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
	"time"
)

type Templates struct {
	templates *template.Template
}

func (t *Templates) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	return t.templates.ExecuteTemplate(w, name, data)
}

func newTemplate() *Templates {
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
	Step  string
	Query string
}

func newProgress() Progress {
	return Progress{
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

var ClientUsers = make(Users)

func main() {

	e := echo.New()
	e.Use(middleware.Logger())
	e.Static("/css", "web/css")
	e.Static("/js", "web/js")
	e.Static("/assets", "web/assets")

	e.Renderer = newTemplate()

	e.GET("/", index)
	e.POST("/auth", auth)
	e.GET("/redirect", redirect)
	e.POST("/token-exchange", tokenExchange)
	e.POST("/refresh", refresh)
	e.GET("/secrets", secrets)
	// @TODO Remove poor mans data wipe.
	e.GET("/reset", reset)

	e.Logger.Fatal(e.Start(":9002"))
}

func index(c echo.Context) error {
	data := newData()
	return c.Render(200, "index", data)
}

func auth(c echo.Context) error {
	website := c.FormValue("url")
	formData := newFormData()
	data := newData()
	data.Progress.Step = "authorization-request"

	indieAuthClientUser, err := newUser(website)
	if err != nil {
		formData.Errors["url"] = fmt.Sprintf("Error when trying to parse the url: %v", err)
		return c.Render(http.StatusUnprocessableEntity, "login-form", formData)
	}
	indieAuthClient := indieAuthClientUser.client

	ClientUsers[indieAuthClient.Identifier.ProfileURL] = indieAuthClientUser

	formData.Values["url"] = website
	formData.Values["authorization_endpoint"] = indieAuthClient.Endpoint.AuthURL
	formData.Values["token_endpoint"] = indieAuthClient.Endpoint.TokenURL

	c.Render(http.StatusOK, "login-form", formData)
	c.Render(http.StatusOK, "auth-form", formData)
	c.Render(http.StatusOK, "url", indieAuthClient.GetAuthorizationRequestURL())

	return c.Render(http.StatusOK, "progress", data.Progress)
}

func redirect(c echo.Context) error {
	code := c.QueryParam("code")
	state := c.QueryParam("state")
	me := c.QueryParam("me")
	// Apparently this is optional, or indieauth.com doesn't implement it.
	issuer := c.QueryParam("iss")
	data := newData()
	data.Progress.Step = "redeeming-authorization-code"
	formData := newFormData()
	id, err := url.QueryUnescape(me)

	formData.Values["code"] = code
	formData.Values["state"] = state
	formData.Values["me"] = me
	formData.Values["iss"] = issuer
	formData.Values["url"] = id

	if err != nil {
		formData.Errors["url"] = fmt.Sprintf("Error when unescaping the me value received: %v", err)
		return c.Render(http.StatusUnprocessableEntity, "code-exchange-form", formData)
	}

	u, ok := ClientUsers[id]

	if !ok {
		formData.Errors["url"] = fmt.Sprintf("No user for id: %v was found registered", id)
		return c.Render(http.StatusUnprocessableEntity, "code-exchange-form", formData)
	}

	data.RedirectURL = u.client.RedirectURL
	formData.Values["authorization_endpoint"] = u.client.Endpoint.AuthURL
	formData.Values["token_endpoint"] = u.client.Endpoint.TokenURL

	data.Form = formData

	return c.Render(http.StatusOK, "index", data)
}

func tokenExchange(c echo.Context) error {
	code := c.FormValue("code")
	state := c.FormValue("state")
	me := c.FormValue("me")
	issuer := c.FormValue("iss")
	data := newData()
	formData := newFormData()
	formData.Values["code"] = code
	formData.Values["state"] = state
	formData.Values["me"] = me
	formData.Values["iss"] = issuer

	id, err := url.QueryUnescape(me)
	if err != nil {
		formData.Errors["url"] = fmt.Sprintf("Error when unescaping the me value received: %v", err)
		return c.Render(http.StatusUnprocessableEntity, "code-exchange-form", formData)
	}

	formData.Values["url"] = id
	u, ok := ClientUsers[id]

	if !ok {
		formData.Errors["url"] = fmt.Sprintf("No user for id: %v was found registered", id)
		return c.Render(http.StatusUnprocessableEntity, "code-exchange-form", formData)
	}

	token, err := u.client.TokenExchange(state, code, issuer)
	if err != nil {
		formData.Errors["url"] = fmt.Sprintf("Error when attempting to exchange the token: %v", err.Error())
		return c.Render(http.StatusUnprocessableEntity, "code-exchange-form", formData)
	}

	data.Progress.Step = "refresh"

	// Write a cookie
	cookie := new(http.Cookie)
	cookie.Name = "indieAuthClient"
	cookie.Value = token
	cookie.HttpOnly = true
	cookie.Expires = time.Now().Add(24 * time.Hour)
	c.SetCookie(cookie)

	formData.Values["token"] = token
	formData.Values["refresh"] = u.client.Token.RefreshToken
	formData.Values["expires_in"] = "1"

	c.Render(http.StatusOK, "progress", data.Progress)
	c.Render(http.StatusOK, "refresh-form", formData)
	return c.Render(http.StatusOK, "code-exchange-form", formData)
}

func refresh(c echo.Context) error {
	data := newData()
	return c.Render(200, "refresh-form", data)
}

func reset(c echo.Context) error {
	ClientUsers = make(Users)
	c.SetCookie(&http.Cookie{
		Name:     "indieAuthClient",
		Value:    "",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
	})
	data := newData()

	return c.Render(http.StatusOK, "index", data)
}

func secrets(c echo.Context) error {
	data := newData()
	cookie, err := c.Cookie("indieAuthClient")
	if err != nil {
		log.Printf("\n\n--Encountered an error %v", err.Error())
		return c.Render(http.StatusForbidden, "secrets", data)
	}
	token := cookie.Value
	log.Printf("User token is %v", token)

	data.Authenticated = true

	// @TODO Clean the "data" structure up to be more sane
	return c.Render(http.StatusOK, "secrets", data)
}
