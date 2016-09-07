"use strict";

var cookieParser = require('cookie-parser'),
    basicAuth    = require('basic-auth'),
    utils        = require('../utils'),
    Promise      = require('bluebird'),
    Auth         = require('pouchdb-auth'),
    crypto       = require('crypto-lite').crypto;

var SECTION = 'couch_httpd_auth';
var PROXY_AUTH_CONFIG = /{couch_httpd_auth,\s*proxy_authentication_handler}/;

module.exports = function (app) {
  var usersDBPromise, refreshUsersDBImpl;

  utils.requires(app, 'config-infrastructure');
  utils.requires(app, 'logging-infrastructure');

  var config = app.couchConfig;
  config.registerDefault(SECTION, 'authentication_db', '_users');
  config.registerDefault(SECTION, 'timeout', 600);
  config.registerDefault(SECTION, 'secret', Auth.generateSecret());
  config.registerDefault(SECTION, 'iterations', 10);
  config.registerDefault(SECTION, 'proxy_use_secret', false);
  config.registerDefault(SECTION, 'x_auth_roles', 'X-Auth-CouchDB-Roles');
  config.registerDefault(SECTION, 'x_auth_token', 'X-Auth-CouchDB-Token');
  config.registerDefault(SECTION, 'x_auth_username', 'X-Auth-CouchDB-UserName');

  // explain how to activate the auth db logic.
  app.dbWrapper.registerWrapper(function (name, db, next) {
    if (name === getUsersDBName()) {
      return db.useAsAuthenticationDB({
        isOnlineAuthDB: false,
        timeout: app.couchConfig.get(SECTION, 'timeout'),
        secret: app.couchConfig.get(SECTION, 'secret'),
        iterations: app.couchConfig.get(SECTION, 'iterations'),
        admins: app.couchConfig.getSection('admins')
      });
    }
    return next();
  });

  app.daemonManager.registerDaemon({
    start: function (PouchDB) {
      PouchDB.plugin(Auth);

      refreshUsersDBImpl = function () {
        usersDBPromise = utils.getUsersDB(app, PouchDB);
      };
      refreshUsersDB();
      PouchDB.on('destroyed', onDestroyed);
    },
    stop: function (PouchDB) {
      PouchDB.removeListener('destroyed', onDestroyed);
    }
  });

  // utils
  var getUsersDBName = utils.getUsersDBName.bind(null, app);

  function getUsersDB() {
    // calls itself until usersDBPromise is a available
    if (!usersDBPromise) {
      return new Promise(function (resolve) {
        setImmediate(function () {
          resolve(getUsersDB());
        });
      });
    }
    return usersDBPromise;
  }

  function onDestroyed(dbName) {
    // if the users db was removed, it should re-appear.
    if (dbName === getUsersDBName()) {
      refreshUsersDB();
    }
  }

  function refreshUsersDB() {
    return refreshUsersDBImpl();
  }

  function isProxyAuthEnabled() {
    var handlers = app.couchConfig.get("httpd", "authentication_handlers");
    if (typeof handlers !== "string") {
      return false;
    }
    return Boolean(handlers.match(PROXY_AUTH_CONFIG));
  }

  // ensure there's always a users db
  app.couchConfig.on(SECTION + '.authentication_db', refreshUsersDB);
  app.couchConfig.on(SECTION + '.timeout', refreshUsersDB);
  app.couchConfig.on(SECTION + '.secret', refreshUsersDB);
  app.couchConfig.on(SECTION + '.iterations', refreshUsersDB);
  app.couchConfig.on('admins', refreshUsersDB);

  // routing
  app.use(cookieParser());

  app.use(function (req, res, next) {
    var proxyEnabled = isProxyAuthEnabled();

    // TODO: TIMING ATTACK
    Promise.resolve().then(function() {
      if (!proxyEnabled) {
        throw {};
      }

      return buildProxyAuthSession(req);
    }).catch(function (err) {
      return buildCookieSession(req, res);
    }).catch(function (err) {
      return buildBasicAuthSession(req);
    }).then(function (result) {
      req.couchSession = result;
      var handlers = ['cookie', 'default'];
      if (proxyEnabled) {
        handlers.unshift("proxy");
      }
      req.couchSession.info.authentication_handlers = handlers;
      next();
    }).catch(function (err) {
      utils.sendError(res, err);
    });
  });

  function buildCookieSession(req, res) {
    var sessionID = (req.cookies || {}).AuthSession;
    if (!sessionID) {
      throw new Error("No cookie, so no cookie auth.");
    }
    return getUsersDB().then(function (db) {
      return db.multiUserSession(sessionID);
    }).then(function (session) {
      if (session.info.authenticated) {
        res.cookie('AuthSession', session.sessionID, {httpOnly: true});
        delete session.sessionID;
        session.info.authenticated = 'cookie';
        logSuccess('cookie', session);
      }
      return session;
    });
  }

  function logSuccess(type, session) {
    var msg = 'Successful ' + type + ' auth as: "' + session.userCtx.name + '"';
    app.couchLogger.debug(msg);
  }

  function buildBasicAuthSession(req) {
    var userInfo = basicAuth(req);
    var db;
    var initializingDone = getUsersDB().then(function (theDB) {
      db = theDB;
    });
    if (userInfo) {
      initializingDone = initializingDone.then(function () {
        return db.multiUserLogIn(userInfo.name, userInfo.pass);
      });
    }
    return initializingDone.then(function (info) {
      return db.multiUserSession((info || {}).sessionID);
    }).then(function (session) {
      delete session.sessionID;

      if (session.info.authenticated) {
        session.info.authenticated = 'default';
        logSuccess('http basic', session);
      }
      return session;
    });
  }

  function buildProxyAuthSession(req) {
    var useSecret = app.couchConfig.get(SECTION, 'proxy_use_secret');
    var headers = {
      roles: app.couchConfig.get(SECTION, 'x_auth_roles'),
      token: app.couchConfig.get(SECTION, 'x_auth_token'),
      name: app.couchConfig.get(SECTION, 'x_auth_username')
    };
    var name = req.get(headers.name);
    var roles = req.get(headers.roles);

    if (name == null && roles == null) {
      throw new Error('missing proxy auth headers');
    }

    if (useSecret) {
      var secret = app.couchConfig.get(SECTION, 'secret');
      var token = req.get(headers.token);

      if (!token) {
        throw new Error('missing proxy token');
      }

      if (token !== crypto.hmac('sha1', secret, name)) {
        throw new Error('token does not match');
      }
    }

    return getUsersDB().then(function (db) {
      return {
        userCtx: {
          name: name || null,
          roles: (roles || "").split(",")
            .map(function(r) {
              return r.trim();
            })
            .filter(Boolean)
        },
        info: {
          authenticated: 'proxy',
          authentication_db: db._db_name
        }
      };
    });
  }
};
