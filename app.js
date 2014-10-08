var express = require('express');
var path = require('path');
var favicon = require('static-favicon');
var logger = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var session = require('express-session');
var passport = require('passport');
var TwitterStrategy = require('passport-twitter').Strategy;
var async = require('async');
var _ = require('lodash');
var moment = require('moment');
var RedisStore = require('connect-redis')(session);
var redis = require('./lib/redis');

var config = require('./config');

var TWITTER_CONSUMER_KEY = config.twitter.key;
var TWITTER_CONSUMER_SECRET = config.twitter.secret;
var CALLBACKURL;
if (process.env.REDISTOGO_URL) {
  CALLBACKURL = 'http://twitterfriendscleaner.herokuapp.com/auth/twitter/callback';
} else {
  CALLBACKURL = 'http://localhost:3000/auth/twitter/callback';
}

//var routes = require('./routes/index');
var login = require('./routes/login');

var app = express();

// passport setup
passport.serializeUser(function(user, done){
  done(null, user);
});

passport.deserializeUser(function(obj, done){
  done(null, obj);
});

passport.use(new TwitterStrategy({
  consumerKey: TWITTER_CONSUMER_KEY,
  consumerSecret: TWITTER_CONSUMER_SECRET,
  callbackURL: CALLBACKURL
}, function(token, tokenSecret, profile, done){
  profile.twitter_token = token;
  profile.twitter_token_secret = tokenSecret;

  process.nextTick(function (){
    return done(null, profile);
  });
}));

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(favicon());
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded());
app.use(cookieParser());
var url = require('url');
var parsed_url = url.parse(process.env.REDISTOGO_URL || 'http://localhost:6379');
var parsed_auth = (parsed_url.auth || '').split(':');
app.use(session({
  store: new RedisStore({
    host: parsed_url.hostname,
    port: parsed_url.port,
    pass: parsed_auth[1],
    ttl: 1000000
  }),
  secret: 'danshari'
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.static(path.join(__dirname, 'public')));

var ensureAuthenticated = function(req, res, next){
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
};

app.get('/', ensureAuthenticated,
  function(req, res){
    redis.hget(req.user.twitter_token, 'list', function(err, user_status){
      if (err) {
        return res.send(err, 500);
      }
      if (!user_status) {
        passport._strategies.twitter._oauth.getProtectedResource('https://api.twitter.com/1.1/friends/ids.json','GET',req.user.twitter_token,req.user.twitter_token_secret,
          function (err, data){
            if (err) {
              if (err.message === 'Over capacity') {
                return res.render('error');
              }
              return res.send(err, 500);
            }

            var jsonObj = JSON.parse(data);
            var ids = jsonObj.ids;
            var b = ids.length;
            var idArray = [];
            for (var i = 0; i < Math.ceil(b / 100); i++) {
              var j = i * 100;
              var p = ids.slice(j, j + 100);
              idArray.push(p);
            }
            var parallels = [];
            idArray.forEach(function(ids){
              parallels.push(function(done){
                passport._strategies.twitter._oauth.getProtectedResource('https://api.twitter.com/1.1/users/lookup.json?user_id=' + ids.join(','),'GET',req.user.twitter_token,req.user.twitter_token_secret,
                  function(err, data){
                    if (err) {
                      if (err.message === 'Over capacity') {
                        return res.render('error');
                      }
                      return res.send(err, 500);
                    }
                    var json = JSON.parse(data);
                    done(null, json);
                  }
                );
              });
            });
            async.parallel(parallels, function(err, results){
              if (err) {
                return res.send(err, 500);
              }
              var users = [];
              var status = [];
              results.forEach(function(result){
                Array.prototype.push.apply(users, result);
              });
              users.forEach(function(user){
                if (user.status) {
                  status.push({text: user.status.text, created_at: user.status.created_at, id: user.status.id, id_str: user.status.id_str});
                } else {
                  status.push({text: 'none', created_at: 'none', id: 'none', id_str: ''});
                }
              });
              for (var ite=0; ite<users.length; ite++) {
                var user = users[ite];
                users[ite] = {name: user.name, screen_name: user.screen_name, id: user.id, profile_image_url: user.profile_image_url};
              }
              var now = moment();
              for (var i = 0; i < users.length; i++) {
                var time = status[i].created_at;
                var createdTime = moment(time, "ddd MMM D HH:mm:ss ZZ YYYY");
                if (now.diff(createdTime, 'months') <= 1) {
                  delete users[i];
                  delete status[i];
                }
              }
              users = _.compact(users);
              status = _.compact(status);
              redis.hset(req.user.twitter_token, 'list', JSON.stringify({users: users, status: status}));
              redis.expire(req.user.twitter_token, 60*7);
              res.render('index', {title: 'twitter friends cleaner', users: users, status: status });
            });
          }
        );
      } else {
        user_status = JSON.parse(user_status);
        res.render('index', {title: 'twitter friends cleaner', users: user_status.users, status: user_status.status });
      }
    });
  }
);
app.get('/login', login);

app.get('/remove/:id', ensureAuthenticated, function(req, res){
  var id = parseInt(req.params.id, 10);
  if (!id) {
    return res.send(new Error('invalid id'), 400);
  }
  passport._strategies.twitter._oauth.getProtectedResource(
    'https://api.twitter.com/1.1/friendships/destroy.json?user_id='+id,
    'POST',
    req.user.twitter_token,
    req.user.twitter_token_secret,
    function(err){
      if (err || !req.user) {
        return console.log(err);
      }
      redis.hget(req.user.twitter_token, 'list',function(err,result){
        if (err) { return res.send(err, 500); }
        var userStatus = JSON.parse(result);
        if (!userStatus || !userStatus.users) {
          return res.send(new Error('Fuckin user'), 500);
        }
        for (var i=0; i<userStatus.users.length; i++) {
          if (userStatus.users[i].id === id) {
            delete userStatus.users[i];
            delete userStatus.status[i];
          }
        }
        userStatus.users = _.compact(userStatus.users);
        userStatus.status = _.compact(userStatus.status);
        redis.hset(req.user.twitter_token, 'list', JSON.stringify(userStatus));
        redis.expire(req.user.twitter_token, 60*7);

      });
    }
  );
  return res.send(200);
});

app.get('/auth/twitter', passport.authenticate('twitter'));
app.get('/auth/twitter/callback', passport.authenticate('twitter', {
  successRedirect: '/',
  failureRedirect: '/login'
}));

/// catch 404 and forward to error handler
app.use(function(req, res, next) {
    var err = new Error('Not Found');
    err.status = 404;
    next(err);
});

/// error handlers

// development error handler
// will print stacktrace
if (app.get('env') === 'development') {
    app.use(function(err, req, res) {
        res.status(err.status || 500);
        res.render('error', {
            message: err.message,
            error: err
        });
    });
}

// production error handler
// no stacktraces leaked to user
app.use(function(err, req, res) {
    res.status(err.status || 500);
    res.render('error', {
        message: err.message,
        error: {}
    });
});

module.exports = app;
