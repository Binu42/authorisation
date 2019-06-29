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

mongoose.connect('mongodb+srv://admin-Binu:'+ process.env.password +'@cluster0-9npsv.mongodb.net/userDB', {
  useNewUrlParser: true
});
mongoose.set('useCreateIndex', true);
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

passport.use(new LinkedInStrategy({
    clientID: process.env.linkedin_CLIENT_ID,
    clientSecret: process.env.linkedin_CLIENT_SECRET,
    callbackURL: "https://secretwhisper.herokuapp.com/auth/linkedin/secrets",
    scope: ['r_emailaddress', 'r_liteprofile'],
    state: true,
  },
  // function (accessToken, refreshToken, profile, done) {
  //   console.log(profile);
  //   // asynchronous verification, for effect...
  //   process.nextTick(function () {
  //     // To keep the example simple, the user's LinkedIn profile is returned to
  //     // represent the logged-in user. In a typical application, you would want
  //     // to associate the LinkedIn account with a user record in your database,
  //     // and return that user instead.
  //     return done(null, profile);
  //   });
  // }
  function (accessToken, refreshToken, profile, cb) {
    User.findOrCreate({
      linkedinId: profile.id,
      name: profile.displayName
    }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/', function (req, res) {
  res.render('home');
});

app.get('/auth/google',
  passport.authenticate('google', {
    scope: ['profile']
  })
);

app.get('/auth/google/secrets',
  passport.authenticate('google', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/github',
  passport.authenticate('github'));

app.get('/auth/github/secrets',
  passport.authenticate('github', {
    failureRedirect: '/login'
  }),
  function (req, res) {
    // Successful authentication, redirect home.
    res.redirect('/secrets');
  });

app.get('/auth/linkedin',
  passport.authenticate('linkedin'),
  function (req, res) {
    // The request will be redirected to LinkedIn for authentication, so this
    // function will not be called.
  });

app.get('/auth/linkedin/secrets', passport.authenticate('linkedin', {
  successRedirect: '/secrets',
  failureRedirect: '/login'
}));

app.get('/login', function (req, res) {
  res.render('login');
});

app.get('/register', function (req, res) {
  res.render('register');
});

app.get('/secrets', function (req, res) {
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
});

app.get('/submit', function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect('/login');
  }
});

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

app.get('/logout', function (req, res) {
  req.logout();
  res.redirect('/');
});

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

app.get('/privacy', function(req, res){
  res.render('privacy');
});

app.listen(process.env.PORT || 3000, function (req, res) {
  console.log('server is running at port 3000');
});