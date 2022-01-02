require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const { initialize } = require('passport');

const app = express();

const port = process.env.PORT || 3000;
 
app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");

app.use(session({
    secret: "Our little Secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    facebookId: String,
    secret: Array
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
    done(null, user.id);
  });
  
  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo" 
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.FACEBOOK_APP_ID,
    clientSecret: process.env.FACEBOOK_APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
        User.findOrCreate({
      facebookId: profile.id
    }, function(err, user) {
      return cb(err, user);
    });
  }
));
app.get("/auth/facebook/secrets", 
passport.authenticate('facebook', { failureRedirect: '/login' }),
function(req, res) {
  res.redirect('/secrets');
});
 app.get("/auth/facebook",
 
    passport.authenticate("facebook")
 
  );
  app.get("/auth/facebook/secrets", 
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });
 
app.get('/', (req, res) => {
  res.render('home');
});

app.route('/auth/google')

  .get(passport.authenticate('google', {

    scope: ['profile']

}));

  app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });
 
app.get('/login', (req, res) => {
  res.render('login');
});
 
app.get('/register', (req, res) => {
  res.render('register');
});

app.get("/secrets",function(req,res){
  User.find({secret:{$ne:null}},function (err, users){
    if(!err){
      if (users){
        res.render("secrets",{usersWithSecrets:users});
      }else {
        console.log(err);
      }
    }else {
      console.log(err);
    }
  });
});

app.route("/submit")
.get(function (req,res){
  if(req.isAuthenticated()){
    User.findById(req.user.id,function (err,foundUser){
      if(!err){
        res.render("submit",{secrets:foundUser.secret});
      }
    })
  }else {
    res.redirect("/login");
  }
})
.post(function (req, res){
  if(req.isAuthenticated()){
    User.findById(req.user.id,function (err, user){
      user.secret.push(req.body.secret);
      user.save(function (){
        res.redirect("/secrets");
      });
    });
 
  }else {
   res.redirect("/login");
  }
});

app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});


app.post("/register", (req, res) => {

    User.register({username: req.body.username}, req.body.password, (err, user) => {
        if (err) {
            console.log(err);
            res.redirect("/register");
        }else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            })   
        }
    });

});

app.post("/login", (req, res) => {
    const user = new User({
        username: req.body.username,
        password: req.body.password
    })

    req.login(user, (err) => {
        if (err){
            console.log(err);
        }else{
            passport.authenticate("local");
            res.redirect("/secrets");
        }
    });


});
app.post("/submit/delete",function (req, res){
  if(req.isAuthenticated()){
    User.findById(req.user.id, function (err,foundUser){
      foundUser.secret.splice(foundUser.secret.indexOf(req.body.secret),1);
      foundUser.save(function (err) {
        if(!err){
          res.redirect("/submit");
        }
      });
    });
  }else {
    res.redirect("/login");
  }
});


 
app.listen(port, () => console.log(`Server started at port: ${port}`)
);
