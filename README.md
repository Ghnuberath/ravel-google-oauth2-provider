# ravel-google-oauth2-provider

> Ravel AuthorizationProvider for Google OAuth2

**Note:** This module is currently untested.

## Example usage:

*app.js*
```javascript
const app = new require('ravel')();
const GoogleOauth2Provider = require('ravel-google-oauth2-provider');
new GoogleOauth2Provider(app);
// ... other providers and parameters
app.init();
// ... the rest of your Ravel app
```

## Configuration

Requiring the `ravel-google-oauth2-provider` module will register configuration parameters with Ravel which must be supplied via `.ravelrc` or `app.set()`:

*.ravelrc*
```json
{
  "google auth callback url" : "http://localhost:8080",
  "google auth path": "/auth/google",
  "google auth callback path": "/auth/google/callback",
  "google client id": "YOUR_CLIENT_ID",
  "google client secret" : "YOUR_CLIENT_SECRET"  
}
```

Note that `google auth callback url` should be the external url for your application. Only change `google auth path` and `google auth callback path` if those routes collide with your application - otherwise they will receive the given default values.

You'll also need to implement an `@authconfig` module like this:

*modules/authconfig.js*
```js
'use strict';

const Ravel = require('ravel');
const inject = Ravel.inject;
const Module = Ravel.Module;
const authconfig = Module.authconfig;

@authconfig
@inject('user-profiles')
class AuthConfig extends Module {
  constructor(userProfiles) {
    this.userProfiles = userProfiles;
  }
  serializeUser(profile) {
    // serialize profile to session using the id field
    return Promise.resolve(profile.id);
  }
  deserializeUser(id) {
    // retrieve profile from database using id from session
    return this.userProfiles.getProfile(id);
  }
  verify(providerName, ...args) {
    if (providerName === 'google-oauth2-web') {
      const accessToken = args[0];
      const refreshToken = args[1];
      const profile = args[2];
      // TODO something more complex, such as using/storing tokens
      return Promise.resolve(profile);
    }
  }
}

module.exports = AuthConfig;
```
