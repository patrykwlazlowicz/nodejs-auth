const jwt = require('jsonwebtoken');
const LocalStrategy = require('passport-local');
const passport = require('passport');
const passportJwt = require('passport-jwt');

// USER MODEL

const USER_MODEL = {
    USERNAME: 'heyhey',
    PASSWORD: 'adecad1000',
    REALNAME: 'Justyna Juszczak'
};

// PASSPORT STUFF

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

// AUTH INIT

module.exports.init = () => {
    createSignInStrategy();
    createSessionStrategy();
    return passport.initialize();
};

// SIGN IN WITH USER / PASS

module.exports.signInViaMail = (req, res, next, cb) => {
    return passport.authenticate(SIGNIN_VIA_MAIL_STRATEGY,
        PASSPORT_AUTHENTICATE_OPTIONS,
        (err) => {
            if (err) {
                return cb(err, null);
            } else {
                return cb(null, USER_MODEL.USERNAME, generateToken());
            }
        })(req, res, next);
};

// AUTHENTICATION CHECK MIDDLEWARE FUNCTION

module.exports.isSignedOut = (req, res, next) => {
    if (!req.headers || !req.headers.authorization) {
        return next();
    } else {
        return res.status(401).end();
    }
};

module.exports.isSignedIn = (req, res, next) => {
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
};

// TOKEN GENERATION

function generateToken() {
    return jwt.sign({
        username: USER_MODEL.USERNAME,
        realName: USER_MODEL.REALNAME
    }, SERVER_SECRET_KEY, {
        expiresIn: TOKEN_EXPIRES_IN
    });
}

// CREATE SESSION AUTH

function createSessionStrategy() {
    passport.use(SESSION_VIA_MAIL_STRATEGY, new JwtStrategy({
            secretOrKey: SERVER_SECRET_KEY,
            jwtFromRequest: jwtExtractor.fromAuthHeaderAsBearerToken()
        },
        (payload, done) => {
            done(null, payload.user);
        }
    ));
}

// CREATE LOGIN AUTH

function createSignInStrategy() {
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
}


