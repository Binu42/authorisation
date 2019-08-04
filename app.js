require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook').Strategy;
const GitHubStrategy = require('passport-github').Strategy;
const LinkedInStrategy = require('passport-linkedin-oauth2').Strategy;

const app = express();
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

app.use(session({
  secret: "Anything Binu Kumar",
  resave: false,
  saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// connecting to database
mongoose.connect('mongodb+srv://admin-Binu:' + process.env.password + '@cluster0-9npsv.mongodb.net/userDB', {
  useNewUrlParser: true
});
mongoose.set('useCreateIndex', true);

// User Scheme at database
const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  name: String,
  googleId: String,
  secret: [String],
  facebookId: String,
  githubId: String,
  linkedinId: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());
passport.serializeUser(function (user, done) {
  done(null, user.id);
});
passport.deserializeUser(function (id, done) {
  User.findById(id, function (err, user) {
    done(err, user);
  });
});

// Google strategy for authentication
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secretwhisper.herokuapp.com/auth/google/secrets",
    userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo'
  },
  function (accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({
      googleId: profile.id,
      name: profile.displayName
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Facebook strategy for authentication
passport.use(new FacebookStrategy({
    clientID: process.env.fb_ID,
    clientSecret: process.env.fb_app_SECRET,
    callbackURL: "https://secretwhisper.herokuapp.com/auth/facebook/secrets"
  },
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      facebookId: profile.id,
      name: profile.displayName
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Github strategy for authentication
passport.use(new GitHubStrategy({
    clientID: process.env.github_CLIENT_ID,
    clientSecret: process.env.github_CLIENT_SECRET,
    callbackURL: "https://secretwhisper.herokuapp.com/auth/github/secrets"
  },
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      githubId: profile.id,
      name: profile.displayName
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Linkedin strategy for authentication
passport.use(new LinkedInStrategy({
  clientID: process.env.linkedin_CLIENT_ID,
  clientSecret: process.env.linkedin_CLIENT_SECRET,
  callbackURL: "https://secretwhisper.herokuapp.com/auth/linkedin/secrets",
  scope: ['r_emailaddress', 'r_liteprofile'],
  state: true,
}, function (accessToken, refreshToken, profile, cb) {
  User.findOrCreate({
    linkedinId: profile.id,
    name: profile.displayName
  }, function (err, user) {
    return cb(err, user);
  });
}));

// Home router
app.get('/', function (req, res) {
  res.render('home');
});

// router for authorising google account
app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile']
  })
);

// router to receive request result from google
app.get('/auth/google/secrets',
  passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

// router for authorising facebook account
app.get('/auth/facebook',
  passport.authenticate('facebook'));

// router to receive request from facebook
app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

// router for authorising Github account
app.get('/auth/github',
  passport.authenticate('github'));

// router to receive request from Github
app.get('/auth/github/secrets',
  passport.authenticate('github', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    // Successful authentication, redirect secrets.
    res.redirect('/secrets');
  });

// router for authorising linkedin account
app.get('/auth/linkedin',
  passport.authenticate('linkedin'),
  function (req, res) {
    // The request will be redirected to LinkedIn for authentication, so this
    // function will not be called.
  });

// router to receive request from linkedin
app.get('/auth/linkedin/secrets', passport.authenticate('linkedin', {
  successRedirect: '/secrets', // successful authentication, redirect to secrets.
  failureRedirect: '/login' // else redirect login
}));

// router for login page
app.get('/login', function (req, res) {
  res.render('login');
});

// router for register page
app.get('/register', function (req, res) {
  res.render('register');
});

// router for secrets page
app.get('/secrets', function (req, res) {
  if (req.isAuthenticated()) {
    User.find({
      secret: {
        $ne: null
      }
    }, function (error, founduser) {
      if (error) {
        console.log(error);
      } else {
        if (founduser) {
          res.render('secrets', {
            usersWithSecrets: founduser
          });
        }
      }
    });
  }else{
    res.redirect('/login');
  }
});

// router for submitting secrets
app.get('/submit', function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect('/login');
  }
});

// router for when secrets are submitted
app.post('/submit', function (req, res) {
  const submitedSecret = req.body.secret;
  User.findById(req.user.id, function (error, user) {
    if (error) {
      console.log(error);
    } else {
      if (user) {
        user.secret.push(submitedSecret);
        user.save(function (error) {
          if (error) {
            console.log(error);
          } else {
            res.redirect("/secrets");
          }
        });
      }
    }
  });
});

// Router for logout of users
app.get('/logout', function (req, res) {
  req.logout();
  res.redirect('/');
});

// router for creating new user and getting there submitted data
app.post('/register', function (req, res) {
  User.register({
    username: req.body.username
  }, req.body.password, function (error, user) {
    if (error) {
      console.log(error);
      res.redirect('/register');
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect('/secrets');
      });
    }
  });
});

// router for login of user and getting there submitted data and matching it with our own database
app.post('/login', function (req, res) {
  const user = new User({
    username: req.body.username, // Twist
    password: req.body.password
  });
  req.login(user, function (error) {
    if (error) {
      console.log(error);
      res.redirect('/login');
    } else {
      passport.authenticate('local')(req, res, function () {
        res.redirect('/secrets');
      });
    }
  });
});

// Privacy page for getting authentication of facebook.
app.get('/privacy', function (req, res) {
  res.render('privacy');
});

app.listen(process.env.PORT || 4000, function (req, res) {
  console.log('server is running at port 4000');
});