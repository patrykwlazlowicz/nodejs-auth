const bodyParser = require('body-parser');
const express = require('express');
const jwt = require('jsonwebtoken');
const LocalStrategy = require('passport-local');
const morgan = require('morgan');
const passport = require('passport');
const passportJwt = require('passport-jwt');
const path = require('path');
const protocol = require('http');
const serveStatic = require('serve-static');
const util = require('util');

// USER MODEL

const USER_MODEL = {
    USERNAME: 'heyhey',
    PASSWORD: 'adecad1000',
    REALNAME: 'Justyna Juszczak'
};

// EXPRESS STUFF

const app = express();

app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(serveStatic(path.join(__dirname, '.')));

// PASSPORT STUFF
// THE FLESH IS HERE :)

const JwtStrategy = passportJwt.Strategy;
const jwtExtractor = passportJwt.ExtractJwt;

// AUTH CONFIG
const SERVER_SECRET_KEY = 'BlueBrick';
const TOKEN_EXPIRES_IN = '1h';
const SIGNIN_VIA_MAIL_STRATEGY = 'signin-via-mail';
const SESSION_VIA_MAIL_STRATEGY = 'session-via-mail';
const PASSPORT_AUTHENTICATE_OPTIONS = {
    session: false
};

// CREATE LOGIN AUTH
passport.use(SIGNIN_VIA_MAIL_STRATEGY, new LocalStrategy({
        usernameField: 'email',
        passwordField: 'password'
    },
    (username, password, done) => {
        if (username === USER_MODEL.USERNAME && password === USER_MODEL.PASSWORD) {
            return done(null);
        } else {
            done(new Error('401'));
        }
    }
));

// CREATE SESSION AUTH
passport.use(SESSION_VIA_MAIL_STRATEGY, new JwtStrategy({
        secretOrKey: SERVER_SECRET_KEY,
        jwtFromRequest: jwtExtractor.fromAuthHeaderAsBearerToken()
    },
    (payload, done) => {
        done(null, payload.user);
    }
));

// SIGN IN WITH USER / PASS

function signInViaMail(req, res, next, cb) {
    return passport.authenticate(SIGNIN_VIA_MAIL_STRATEGY,
        PASSPORT_AUTHENTICATE_OPTIONS,
        (err, user) => {
            if (err) {
                return cb(err, null);
            } else {
                return cb(null, user, generateToken());
            }
        })(req, res, next);
}

function generateToken() {
    return jwt.sign({
        username: USER_MODEL.USERNAME,
        realName: USER_MODEL.REALNAME
    }, SERVER_SECRET_KEY, {
        expiresIn: TOKEN_EXPIRES_IN
    });
}

// AUTHENTICATION CHECK MIDDLEWARE FUNCTION

function isSignedOut(req, res, next) {
    if (!req.headers || !req.headers.authorization) {
        return next();
    } else {
        return res.status(401).end();
    }
}

function isSignedIn(req, res, next) {
    return passport.authenticate(SESSION_VIA_MAIL_STRATEGY,
        PASSPORT_AUTHENTICATE_OPTIONS,
        (err, user) => {
            if (!err && user) {
                res.set('X-Access-Token', generateToken());
                req.user = user;
                next();
            } else {
                return res.status(401).end();
            }
        })(req, res, next);
}

app.use(passport.initialize());

// API ROUTES

const router = express.Router();

router.all('*', function (req, res) {
    return res.sendFile(path.join(__dirname, './views/index.html'));
});

app.post('/signin', isSignedOut, (req, res, next) => {
    signInViaMail(req, res, next, (err) => {
        if (err) {
            console.log(util.inspect(err));
            return res.status(400).json(err);
        } else {
            return res.status(200).json({username: USER_MODEL.USERNAME, token: generateToken()});
        }
    });
});

app.get('/profile', isSignedIn, (req, res) => {
    res.json({realName: req.user.realName});
});

// CREATE SERVER

const server = protocol.createServer(app);

server.listen(9090, '0.0.0.0', function () {
    console.log('Server application started');
});


