const auth = require('./auth');
const bodyParser = require('body-parser');
const express = require('express');
const morgan = require('morgan');
const path = require('path');
const protocol = require('http');
const serveStatic = require('serve-static');
const util = require('util');


// EXPRESS STUFF

const app = express();

app.use(morgan('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
    extended: true
}));
app.use(serveStatic(path.join(__dirname, '.')));

app.use(auth.init());

// API ROUTES

app.post('/signin', auth.isSignedOut, (req, res, next) => {
    auth.signInViaMail(req, res, next, (err, username, token) => {
        if (err) {
            console.log(util.inspect(err));
            return res.status(400).json(err);
        } else {
            return res.status(200).json({username: username, token: token});
        }
    });
});

app.post('/keepsession', auth.isSignedIn, (req, res) => {
    res.json({username: req.user.username});
});

app.get('/user/profile', auth.isSignedIn, (req, res) => {
    res.json({realName: req.user.realName});
});

app.all('*', function (req, res) {
    console.log(path.join(__dirname, './views/index.html'));
    return res.sendFile(path.join(__dirname, './views/index.html'));
});

// CREATE SERVER

const server = protocol.createServer(app);

server.listen(9090, '0.0.0.0', function () {
    console.log('Server application started');
});


