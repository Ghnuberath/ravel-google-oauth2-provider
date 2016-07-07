'use strict';

const https = require('https');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const Ravel = require('ravel');

/**
 * A Ravel AuthorizationProvider for Google OAuth 2.0
 */

class GoogleOAuth2Provider extends Ravel.AuthenticationProvider {
  constructor(ravelInstance) {
    super();
    ravelInstance.registerParameter('google oauth2 web client id', true);
    ravelInstance.registerParameter('google oauth2 web client secret', true);
    ravelInstance.registerParameter('google oauth2 scope', true, ['https://www.googleapis.com/auth/userinfo.profile', 'https://www.googleapis.com/auth/userinfo.email']);
  }

  get name() {
    return 'google-oauth2-web';
  }

  /**
   * Initialize passport.js with a strategy
   *
   * @param koaRouter {Object} An koa-router instance
   * @param passport {Object} A passport.js object
   * @param verify {Function} See passport-google-oauth Strategy verify callback.
   *                          Should be function(accessToken, refreshToken, profile)
   *                          which returns a Promise which resolves with the profile
   */
  init(app, passport, verify) {
    passport.use(new GoogleStrategy({
      clientID: this.ravelInstance.get('google client id'),
      clientSecret: this.ravelInstance.get('google client secret'),
      callbackURL: `${this.ravelInstance.get('google auth callback url')}${this.ravelInstance.get('google auth callback path')}`
    }, verify));


    app.get(this.ravelInstance.get('google auth path'), passport.authenticate('google'));

    app.get(this.ravelInstance.get('google auth callback path'),
      passport.authenticate('google', {
        failureRedirect: this.ravelInstance.get('login route'),
        successRedirect: this.ravelInstance.get('app route')
      })
    );
  }

  /**
   * Does this authorization provider handle the given client type?
   *
   * @param client {String} A client type, such as google-oauth2-web
   * @return {Boolean} true iff this provider handles the given client
   */
  handlesClient(client) {
    return client === 'google-oauth2-web';
  }

  /**
   * Transform a credential for an auth'd user into a user profile, iff the
   * credential is valid for this application.
   *
   * @param credential {String} A credential
   * @param client {String}  A client type, such as google-oauth2-web
   * @return {Promise} resolves with user profile iff the credential is valid for this application, rejects otherwise
   */
  credentialToProfile(credential, client) {
    return new Promise((resolve, reject) => {
      if (client === 'google-oauth2-web') {
        https.get(`https://www.googleapis.com/plus/v1/people/me?access_token=${credential}`, (res) => {
          const body = '';
          res.on('data', (d) => {
            body += d;
          });
          res.on('end', () => {
            try  {
              resolve(JSON.parse(body));
            } catch (err) {
              reject(err);
            }
          });
        }).on('error', (e) => {
          reject(e);
        });
      } else {
        reject(new this.ApplicationError.IllegalValue(`google-oauth2-web provider cannot handle client ${client}`));
      }
    });
  };
}

module.exports = GoogleOAuth2Provider;
