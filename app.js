const express = require('express')
const path = require('path')
const app = express();
const passport = require('passport')
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const port = process.env.PORT || 5000
const session = require('express-session');

const bodyParser = require('body-parser');
app.use(bodyParser.urlencoded({ extended: true }));
// user used for google login 
require('./auth');
app.use(express.json())
app.use(express.static(path.join(__dirname,'client')))

function isloggedIn(req,res,next){
  req.user ? next() : res.sendStatus(401)
}
app.get('/',(req,res)=>{
  res.sendFile('index.html')
})
app.use(session({
  secret: 'mysecret userapi',
  resave: false,
  saveUninitialized: true,
  cookie:{secure:false}
}));
app.use(passport.initialize());
app.use(passport.session())

app.get('/auth/google',
  passport.authenticate('google', { scope: ['email','profile'] }));

app.get('/auth/google/callback', 
  passport.authenticate('google', { 
    successRedirect:'/auth/protected',
    failureRedirect: '/auth/failure' }),
  );

  app.get('/auth/protected',isloggedIn,(req,res)=>{
    let name = req.user.displayName;
    
    console.log(req.user);
    res.send(`Hello welcome Name :${name}`)
  })
  app.get('/auth/faliure',isloggedIn,(req,res)=>{
    res.send("something went wrong is there")
  })

  app.get('/logout',(req,res)=>{
    req.logOut()
    res.redirect('/')
  })

// user can login with facebook

const FacebookStrategy = require('passport-facebook').Strategy;
require('dotenv').config()
passport.use(new FacebookStrategy({
    clientID: process.env.facebook_id,
    clientSecret: process.env.facebook_secret,
    callbackURL: "http://localhost:5000/auth/facebook/callback",
    passReqToCallback:true,
  },
  function(request,accessToken, refreshToken, profile, done) {
   done(null,profile);
  }
));

passport.serializeUser((user,done)=>{
    done(null,user);
})
passport.deserializeUser((user,done)=>{
    done(null,user);
})
app.use(session({
  secret: 'mysecret facebook',
  resave: false,
  saveUninitialized: true,
  cookie:{secure:false}
}));
app.use(passport.initialize());
app.use(passport.session())

app.get('/auth/facebook',
  passport.authenticate('facebook', { scope: ['email'] })
);

app.get('/auth/facebook/callback', 
  passport.authenticate('facebook', { 
    successRedirect:'/auth/protected',
    failureRedirect: '/auth/faliure' }),
);

app.get('/facebook-success', (req, res) => {
  if (req.isAuthenticated()) {
    res.send(`Hello, ${req.user.displayName}!`);
  } else {
    res.send('Not logged in');
  }
})

  // normal user login
  // Set up MongoDB connection
mongoose.connect('mongodb://127.0.0.1:27017/googleauth', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));
db.once('open', () => {
  console.log('Connected to MongoDB');
});

// Define User schema
const userSchema = new mongoose.Schema({
  name:{type:String,required:true},
  email: {type:String,required:true},
  password: {type:String,required:true},
  phone:{type:Number,required:true},
});

const User = mongoose.model('User', userSchema);



// Register user this is for api

app.post('/register-api', async (req, res) => {
  try {
    const {name, email, password,phone } = req.body;
    console.log(email,password); 
    // Hash the password before saving
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      phone
    });
    await newUser.save();
    
    res.status(201).send({status:"success",data:newUser});

  } catch (error) {
    res.status(500).send('Error registering user');
  }
});

// register from the html page
app.get('/register', (req, res) => {
  const filePath = path.join(__dirname, 'client', 'register.html');
  res.sendFile(filePath);
});
// sumbit the data from html 
app.post('/register-form', async(req, res) => {
  const password = req.body.password;
  const email = req.body.email;
  const name = req.body.name;
  const phone = req.body.phone;

  // Hash the password before saving
  const hashedPassword = await bcrypt.hash(password, 10);
  const newUser = new User({
    name,
    email,
    password: hashedPassword,
    phone
  });
  await newUser.save();
  res.redirect('/')
});
// Login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).send('User not found');
    }

    // Compare hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).send('Invalid password');
    }

    // Set the user in the session
    req.session.user = user;

    res.status(200).send({data:user});
  } catch (error) {
    res.status(500).send('Error logging in');
  }
});

// login from html page
app.post('/loginhtml', async (req, res) => {
  try {
    const email = req.body.email;
    const password = req.body.password;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).send('User not found');
    }

    // Compare hashed password
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).send('Invalid password');
    }

    // Set the user in the session
    req.session.user = user;

    res.redirect('/dashboard')
  } catch (error) {
    res.status(500).send('Error logging in');
  }
});

app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }

  res.status(200).send(`Welcome, name :${req.session.user.name} <br>
  ,email:${req.session.user.email},
   phone:${req.session.user.phone}`);
});

app.listen(port,()=>{
  console.log(`listening on the website http://localhost:${port}`);
})

