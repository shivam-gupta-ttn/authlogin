if (process.env.NODE_ENV !== 'production') {
    require('dotenv').config()
}

const express = require('express')
const mongoose = require("mongoose");
const bcrypt = require('bcrypt')
const passport = require('passport')
const flash = require('express-flash')
const session = require('express-session')
const FacebookStrategy = require("passport-facebook")
const {
    userModel
} = require('./model');


const initializePassport = require('./passport-config')
initializePassport(passport, async email =>
    await userModel.findOne({ email: email })
)

const app = express();

app.set('view-engine', 'ejs')
app.use(express.urlencoded({ extended: false }))
app.use(flash())
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}))
app.use(passport.initialize())
app.use(passport.session())

mongoose.connect("mongodb://localhost:27017/userlogin", {
    useNewUrlParser: "true",
});
mongoose.connection.on("error", err => {
    console.log("err", err)
});
mongoose.connection.on("connected", (err, res) => {
    console.log("mongoose is connected")
});

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "http://localhost:3000/auth/facebook/loggedIn"
},
    async function (accessToken, refreshToken, profile, cb) {

        if (userModel.exists({ facebookId: profile.id })) {
            await userModel.findOne({ facebookId: profile.id }, function (err, user) {
                console.log("found===>>", profile)
                return cb(err, user);
            });
        } else {
            await userModel.create({ facebookId: profile.id }, function (err, user) {
                console.log("created====>", profile)
                return cb(err, user);
            })
        }

    }
));

app.get('/', checkAuthenticated, (req, res) => {
    res.render('index.ejs')
})
app.get('/login', checkNotAuthenticated, (req, res) => {
    res.render('login.ejs')
})


app.post('/login', checkNotAuthenticated, passport.authenticate('local', {
    successRedirect: '/',
    failureRedirect: '/login',
    failureFlash: true
}))


app.get('/register', checkNotAuthenticated, (req, res) => {
    res.render('register.ejs')
})

app.post('/register', checkNotAuthenticated, async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10)
        await userModel.create({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword
        })
        res.redirect('/login')

    } catch {
        res.redirect('/register')
    }
})

app.post('/logout', (req, res) => {
    req.logOut()
    res.redirect('/login')
})
app.get('/auth/facebook',
    passport.authenticate('facebook'));

app.get('/auth/facebook/loggedIn',
    passport.authenticate('facebook', { failureRedirect: '/register' }),
    function (req, res) {
        // Successful authentication, redirect home.
        res.redirect('/');
    });

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next()
    }
    res.redirect('/login')
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/')
    }
    next()
}
passport.serializeUser(function (user, done) {
    done(null, user);
});

passport.deserializeUser(function (user, done) {
    done(null, user);
});

app.listen(3000)