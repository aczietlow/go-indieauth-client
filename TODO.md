  
- [x] complete url canonicalization
- [x] Move on to creating the client authorization request
  - The client builds the authorization request including its 
    - [x] client identifier, 
    - [x] requested scope, 
    - [x] state
    - [x] code_verify, code_challenge, code_challenge_method
    - [x] redirect URI.
  - [ ] Then redirects the browser to the authorization endpoint with the constructed request
    - If possible, keep echo server logic within the website implementation and the client implementation agnostic.
    - Test with indieAuth.net
  - [ ] Build indieAuth Server Authorization Endpoint to respond to authorization requests



Post MVP
- [ ] Add support to indieAuthClient to look for auth metadata endpoint
- [ ] Add functionality to indieAuthClient to follow auth metadata URL, parse json, and return the auth and token endpoints
- [ ] Allow for composable [scopes](https://indieauth.spec.indieweb.org/#profile-information-li-1). No need to force profile and email all the time.
- [ ] Add additional code-challenge methods other than SHA256