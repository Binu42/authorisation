//jshint esversion:6
require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
// const encrypt = require('mongoose-encryption');
// const md5 = require('md5');
const bcrypt = require('bcrypt');

const saltRounds = 10;

const app = express();
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
  extended: true
}));

mongoose.connect('mongodb://localhost:27017/userDB', {
  useNewUrlParser: true
});
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true
  },
  password: {
    type: String,
    required: true
  }
});

// Do this before making collections
// const secret = process.env.SECRET;
// userSchema.plugin(encrypt, {secret: secret, encryptedFields: ['password']});
// // /// /////// // / // / / // / // / // / // /

const User = new mongoose.model('User', userSchema);

app.get('/', function (req, res) {
  res.render('home');
});

app.get('/login', function (req, res) {
  res.render('login');
});

app.get('/register', function (req, res) {
  res.render('register');
});

app.post('/register', function (req, res) {
  bcrypt.hash(req.body.password, saltRounds, function (error, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash
    });
    newUser.save(function (error) {
      if (error) {
        console.log(error);
      } else {
        res.render('secrets');
      }
    });
  });
});

app.post('/login', function (req, res) {
  const username = req.body.username;
  const password = req.body.password;
  User.findOne({
    email: username
  }, function (error, foundlist) {
    if (error) {
      console.log(error);
    } else {
      if (foundlist) {
        bcrypt.compare(password, foundlist.password, function (error, result) {
          if(result === true)
            res.render('secrets');
        });
      }
    }
  });
});




app.listen(process.env.PORT || 3000, function (req, res) {
  console.log('server is running at port 3000');
});