'use strict';

var https = require('https');
var GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

module.exports = function(Ravel) {
  var GoogleOAuth2Provider = new Ravel.AuthorizationProvider('google-oauth2');

  //register this as an authorization provider
  var providers = Ravel.get('authorization providers');
  providers.push(GoogleOAuth2Provider);
  Ravel.set('authorization providers', providers);

	//Google OAuth parameters
  Ravel.registerSimpleParameter('google oauth2 web client id', true);
  Ravel.registerSimpleParameter('google oauth2 web client secret', true);
  Ravel.registerSimpleParameter('google oauth2 android client id');
  Ravel.registerSimpleParameter('google oauth2 ios client id');
  Ravel.registerSimpleParameter('google oauth2 ios client secret');


  GoogleOAuth2Provider.init = function(expressApp, passport, authCallback) {
  	expressApp.get('/auth/google', 
	    passport.authenticate('google', {
	      scope:'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email'
	  }));

	  expressApp.get('/auth/google/return',
	    passport.authenticate('google', {
	      scope:'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email', 
	      failureRedirect: Ravel.get('login route'),
	      successRedirect: Ravel.get('app route')
	    })
	  );

	  passport.use(new GoogleStrategy({
	      //https://cloud.google.com/console/project/1084472114850/apiui/credential
	      //https://developers.google.com/+/web/signin/server-side-flow <- Super important
	      clientID:Ravel.get('google oauth2 web client id'),
	      clientSecret:Ravel.get('google oauth2 web client secret'),
	      callbackURL: 'http://' + Ravel.get('app domain') +':' + Ravel.get('app port') + '/auth/google/return'
	    },
	    authCallback
	  ));
  };

  GoogleOAuth2Provider.handlesClient = function(client) {
  	return client === 'google-oauth2-ios' || 'google-oauth2-android' || 'google-oauth2-web';
  };
  
  //Validates a bearer token and caches the result until that token's
  //expire time.
  //TODO do this locally instead of calling googleapis https://developers.google.com/accounts/docs/OAuth2Login#validatinganidtoken
  function validateToken(token, client, callback) {
    //mobile API auth based on google OAuth2 token supplied by client
    //we need to determine who the client is, and map that to a profile 
    //https://developers.google.com/accounts/docs/OAuth2UserAgent#validatetoken
    //http://android-developers.blogspot.ca/2013/01/verifying-back-end-calls-from-android.html
    https.get('https://www.googleapis.com/oauth2/v1/tokeninfo?scope=https://www.googleapis.com/auth/userinfo.profile+https://www.googleapis.com/auth/userinfo.email+&access_token='+token, function(res) {
      var data = '';        
      res.on('data', function(chunk) {
        data+=chunk;
      });
      res.on('end', function() {
        var obj = JSON.parse(data);
        var audience;
        switch(client) {
          case 'google-oauth2-ios':
            audience = Ravel.get('google oauth2 ios client id');
            break;
          case 'google-oauth2-android':
            audience = Ravel.get('google oauth2 android client id');
            break;
          case 'google-oauth2-web':
            /* falls through */
          default:
            audience = Ravel.get('google oauth2 web client id');
            break;
        }
        var message;
        if (res.statusCode > 200 || obj['error']) {
          message = 'Client attempted to access API with an invalid OAuth token=' + token + ' for client \'' + client + '\'';
          Ravel.Log.e(message);
          callback(new Error(message), null);
        } else if (obj['audience'] !== String(audience)) {
          message = 'Client attempted to access API with a valid OAuth token=' + token + ' against client \'' + client + '\', but it is registered to a different application client';
          Ravel.Log.e(message);
          callback(new Error(message), null);
        } else if (obj['user_id']) {
          //allow bypass!
          callback(null, obj);
        } else {
          message = 'Could not translate valid Google OAuth token=' + token + ' into Google client id.';
          Ravel.Log.e(message);
          Ravel.Log.e(obj);
          callback(new Error(message), null);
        }
      });
    });
  }

  //transforms a bearer token into a Google OAuth2.0 profile
  GoogleOAuth2Provider.tokenToProfile = function(token, client, callback) {
    validateToken(token, client, function(err, validity) {
      if (err) {
        callback(err, null);
      } else if (!validity){
        callback(new Error('Unable to retrieve profile using an invalid OAuth token=' + token + ' for client \'' + client + '\''), null);
      } else {
        //token is valid!
        //use Google APIs to retrieve user profile
        //using given token. Token MUST have been requested with the
        //following scopes:
        //- https://www.googleapis.com/auth/userinfo.profile 
        //- https://www.googleapis.com/auth/userinfo.email
        https.get({
            hostname:'www.googleapis.com',
            path:'/plus/v1/people/me/openIdConnect',
            headers: {
                'Authorization':'Bearer ' + token
            }
        }, function(res) {
            var data = '';
            res.on('data', function(chunk) {
                data+=chunk;
            });
            res.on('end', function() {
                var obj = JSON.parse(data);
                if (res.statusCode > 200 || obj['error']) {
                    var message = 'Could not translate valid Google OAuth token=' + token + ' into OAuth profile for client \'' + client + '\'';
                    Ravel.Log.e(message);
                    Ravel.Log.e(obj);
                    callback(new Error(message), null);
                } else {
                    var profile = {
                        displayName:obj.name,
                        emails:obj['email_verified'] ? [obj['email']] : [],
                        name: {givenName:obj['given_name'], familyName:obj['family_name']},
                        _json:{picture:obj['picture']}
                    };
                    callback(null, profile, validity['expires_in']);
                }
            });
        });
      }
    });
  };
};