# hyper-idp

Authentication server that redirects logins to the OIDC provider (tested with Auth0)
and sets id_token and access_token JWT tokens as HttpOnly domain cookies in the 
oauth2 callback response via Set-Cookie headers.

Browser applications can then make authenticated requests with the javascript fetch
api by adding the `{ credentials: "include" }` option.

To be useful, hyper-idp must be running on the same domain as the frontend
applications.
