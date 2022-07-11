# Scaffold The App
### Our Golang application involves these four routes:

`GET /` - Renders the homepage.

`GET /login` - Renders the "Log In" page.

`GET /profile` - Renders the "Profile" page.

`POST /login` - Authenticates the user and stores the token cookie. When successful, redirects the user to the "Profile" page.

`POST /logout` - Unauthenticates the user and deletes the token cookie. When successful, redirects the user back to the homepage.
