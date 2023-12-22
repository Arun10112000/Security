require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const findOrCreate = require("mongoose-findorcreate");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;

const app = express();

app.use(express.static("public"));
app.set('view engine',"ejs");
app.use(bodyParser.urlencoded({
  extended: true
}));

// app use session package
app.use(session({
      secret: "Our little secret.",
      resave: false,
      saveUninitialized: false,
    }));

    app.use(passport.initialize());
    app.use(passport.session());

mongoose.connect('mongodb://localhost:27017/userData');

const userSchema = new mongoose.Schema({
    email:String,
    password:String,
    googleId: String,
    facebookId: String,
    secret: String
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Model
const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());
//Only necessary when using sessions.
// passport.serializeUser(function(user, done) {
//   done(null, user);
// });
passport.serializeUser(function(user, cb) {
  process.nextTick(function() {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function(user, cb) {
  process.nextTick(function() {
    return cb(null, user);
  });
});
// passport.deserializeUser(function(user, done) {
//   done(null, user);
// }); 

passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
  clientID: process.env.APP_ID,
  clientSecret: process.env.APP_SECRET,
  callbackURL: "http://localhost:3000/auth/facebook/secretss"
},
function(accessToken, refreshToken, profile, cb) {
  console.log(profile);
  User.findOrCreate({ facebookId: profile.id }, function (err, user) {
    return cb(err, user);
  });
}
));


app.get("/", function(_req, res){
    res.render("home");
});

app.get('/auth/google',
  passport.authenticate('google', { scope: ["profile"] })
);

app.get("/auth/google/secrets",
 passport.authenticate("google", { failureRedirect: "/login" }),
function(req, res) {
 res.redirect("/secrets");
});

app.get("/auth/facebook", 
  passport.authenticate("facebook")
);
 
app.get("/auth/facebook/secretss", 
passport.authenticate("facebook", { failureRedirect: "/login" }),
function(req, res) {
  // Successful authentication, redirect secrets.
  res.redirect("/secrets");
});

app.get("/login", function(_req, res){
    res.render("login");
});

app.get("/register", function(_req, res){
    res.render("register");
});

app.get("/secrets", function (req, res) {
    if (req.isAuthenticated()) {
      res.render("secrets");
    } else {
      res.redirect("/login");
    }
  });

  app.get("/logout", function (req, res, next) {
    req.logout(function (err) {
      if (err) {
        return next(err);
      } else {
        res.redirect("/");
      }
    });
  });

app.post("/register", function(req, res){
    User.register(
        { username: req.body.username },
        req.body.password,
        function (err, user) {
          if (err) {
            console.log(err);
            res.redirect("/register");
          } else {
            passport.authenticate("local")(req, res, function () {
              res.redirect("/secrets");
            });
          }
        }
      );    

});

app.post("/login",function(req,res){
    const user = new User({
        username: req.body.username,
        password: req.body.password,
      });
     
      req.login(user, function (err) {
        if (err) {
          console.log(err);
        } else {
          passport.authenticate("local")(req, res, function () {
            res.redirect("/secrets");
          });
        }
      });
});

app.listen(3000,function(){
    console.log("Server started on port 3000.");
});
