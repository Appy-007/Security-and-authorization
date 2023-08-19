require('dotenv').config();
const express=require('express');
const bodyparser=require('body-parser');
const ejs=require('ejs');
const mongoose=require('mongoose');
const bcrypt=require('bcrypt');
const session =require('express-session');
const passport=require('passport');
const passportLocalMongoose=require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');

const app =express();
app.use(express.static('public'));
app.set('view engine','ejs');
app.use(bodyparser.urlencoded({extended:true}));


app.use(session({
    secret:"process.env.SECRET",
    resave:false,
    saveUninitialized:true
}))
app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://127.0.0.1:7000/userDB",{useNewUrlParser: true});

const userSchema =new mongoose.Schema({
    Email:String,
    Password:String,
    googleId:String,
    Secret:String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);



const User = mongoose.model('User',userSchema);
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
    done(null, user.id); 
});
passport.deserializeUser(function(id, done) {
    User.findById(id)
    .then(user => {
     done(null, user);
    })
    .catch(err => {
      done(err, null);
    });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:7000/auth/google/secrets",
    userProfileURL:"https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.get('/',function(req,res){
    res.render('home');
})

app.get('/login',function(req,res){
    res.render('login');
})

app.get('/secrets',function(req,res){
   User.find({"Secret":{$ne:null}}).then(function(foundUser){
    if(foundUser){
        res.render('secrets',{usersWithSecrets:foundUser})
    }
   }).catch(function(err){
    console.log(err);
   })
})
app.get('/register',function(req,res){
    res.render('register');
})

app.post('/register',function(req,res){
    User.register({username:req.body.username},req.body.password).then(function(user){
        passport.authenticate('local')(req,res,function(){
            res.redirect('/secrets');
        })
    }).catch(function(err){
        console.log(err);
        res.redirect('/register');
    })
    
})

app.post('/login',function(req,res){
   const user=new User({
    username:req.body.username,
    password:req.body.password
   });
   req.login(user,function(err){
    if(err){
        console.log(err);
    }
    else{
        passport.authenticate('local')(req,res,function(){
            res.redirect('/secrets'); 
    })}
   })
})
app.get('/logout', function(req, res, next) {
    req.logout(function(err) {
      if (err) { 
        return next(err); 
        }
      res.redirect('/');
    });
  });

app.get('/auth/google',
  passport.authenticate('google', { scope: ['profile'] }));

  app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/');
});

app.get('/submit',function(req,res){
    if(req.isAuthenticated()){
        res.render('submit');
    }
    else{
        res.redirect('/login');
    }
})

app.post('/submit',function(req,res){
    const submittedSecret=req.body.secret;
    User.findById(req.user.id).then(function(foundUser){
        if(foundUser){
            foundUser.Secret=submittedSecret;
            foundUser.save().then(function(){
                res.redirect('/secrets');
            }).catch(function(err){
                console.log(err);
            })
        }
    }).catch(function(err){
        console.log(err);
    })
})



app.listen(7000,function(){
    console.log("Server is running at port 7000");
})
