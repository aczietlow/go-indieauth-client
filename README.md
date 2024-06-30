# Go Indie Auth Client

[WIP] A client to connect to an indie go server

## How to use

The majority of the logic for the client is available in `pkg/indieAuth/`. Ships with an website built with HTMX and Echo as an example implementation 

To run website locally with live reloading

> go air

Then visit `http://localhost:9002`

## Architecture

- /cmd - main application for this project
  - Note this is currently the controller for the HTMX website. I'm not 100% certain I like bundling the website and the client together, but that's a problem/refactor for future self
- /pkg - library code that's okay for use in external applications. 
  - The indieAuth client is the meat and potatoes of this project
- /tmp - build assets used during compiling and serving the website
- /website - the project's website used as a PoC implementation

## Working with remote IndieAuth Servers

The IndieAuth Server needs to be able to reach both the redirect_uri and client_id URLs. To accomplish this I use ngrok. The following assumes that both ngrok is installed locally and that the local dev address of the indieAuth client website is http://localhost:9002

`ngrok http http://localhost:9002`

Then add the ngrok URL to the config.yaml file.