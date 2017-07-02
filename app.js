/*eslint-env node*/

//------------------------------------------------------------------------------
// node.js starter application for Bluemix
//------------------------------------------------------------------------------

// This application uses express as its web server
// for more info, see: http://expressjs.com
var express = require('express');

// cfenv provides access to your Cloud Foundry environment
// for more info, see: https://www.npmjs.com/package/cfenv
var cfenv = require('cfenv');

//TODO Get details from VCAP_SERVICES

var ldap_url = process.env.LDAP_URL; //"ldap://cap-sg-prd-4.integration.ibmcloud.com:17830";
var ldap_dn = process.env.LDAP_DN; //"cn=root";
var ldap_passwd = process.env.LDAP_DN_PASSWORD;
var ldap_suffix = process.env.LDAP_SUFFIX; // "ou=caseinc,o=sample";
var ldap_user = process.env.LDAP_USERNAME; // "wasadmin"
var ldap_userpasswd = process.env.LDAP_USER_PASSWORD;

// Use LDAP
var ldap = require('ldapjs');

// Use UUID
var uuid = require('uuid');

// create a new express servera
var app = express();

// serve the files out of ./public as our main files
app.use(express.static(__dirname + '/public'));

// get the app environment from Cloud Foundry
var appEnv = cfenv.getAppEnv();

// Process the login form for LDAP
app.get("/quixote", function(req, res) {

	// Data about this session.
	var sessionData = {

		// Information required to access the LDAP directory:
		// URL, suffix, and admin (or read only) credentials.
		ldap: {
			url: ldap_url,
			dn: ldap_dn,
			passwd: ldap_passwd,
			suffix: ldap_suffix
		},

		// Information related to the current user
		uid: ldap_user,
		passwd: ldap_userpasswd,
		dn: "",    // No DN yet

		// Authorizations we already calculated - none so far
		authList: {}
	};

	// Use the administrative account to find the user with that UID
	var adminClient = ldap.createClient({
		url: sessionData.ldap.url
	});

	// Bind as the administrator (or a read-only user), to get the DN for
	// the user attempting to authenticate
	adminClient.bind(sessionData.ldap.dn, sessionData.ldap.passwd, function(err) {

		// If there is an error, tell the user about it. Normally we would
		// log the incident, but in this application the user is really an LDAP
		// administrator.
		if (err != null) {
			res.sendStatus(500);
			adminClient.unbind();
		} else {
			// Search for a user with the correct UID.
			adminClient.search(sessionData.ldap.suffix, {
				scope: "sub",
				filter: "(uid=" + sessionData.uid + ")"
			}, function(err, ldapResult) {
				if (err != null)
					throw err;
				else {
					// If we get a result, then there is such a user.
					ldapResult.on('searchEntry', function(entry) {
            console.log(entry);
						sessionData.dn = entry.dn;
						sessionData.name = entry.object.cn;

						// When you have the DN, try to bind with it to check the password
						var userClient = ldap.createClient({
							url: sessionData.ldap.url
						});
						userClient.bind(sessionData.dn, sessionData.passwd, function(err) {
							if (err == null) {
                console.log(" User found and logon successful ");
								res.sendStatus(200);
								userClient.unbind();
								adminClient.unbind();
							} else {
                console.log(" User found but logon not successful ");
              	res.sendStatus(403);
								userClient.unbind();
								adminClient.unbind();
              }
						}); //END userClient.bind
					}); //END ldapResult.on

					// If we get to the end and there is no DN, it means there is no such user.
					ldapResult.on("end", function() {
						if (sessionData.dn === ""){
              console.log(" No such user ");
              res.sendStatus(403);
							userClient.unbind();
							adminClient.unbind();
            }
					}); //END ldapResult.on
				}
			}); //END adminClient.search
		}
	}); //END adminClient.bind
}); // END app.get

// start server on the specified port and binding host
app.listen(appEnv.port, '0.0.0.0', function() {

  // print a message when the server starts listening
  console.log("server starting on " + appEnv.url);
});
