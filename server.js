const express = require('express')
const cors = require('cors')
const app = express()
const bodyParser = require('body-parser')
const mysql = require('mysql2')
const bcrypt = require('bcrypt')
const saltRounds = 10
const jwt = require('jsonwebtoken');
const secret = 'mysecret'

app.use(cors())

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

require('dotenv').config()

const connection = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE
});

app.post('/register', function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
        connection.query(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [req.body.username, hash],
            function (err, results) {
                if (err) {
                    res.sendStatus(500)
                    console.error(err)
                    next()
                }
                res.status(200).json({ status: 'registered successfully' })
            }
        );
    });
})

app.post('/login', function (req, res, next) {
    connection.query(
        'SELECT * FROM users WHERE username = ?',
        [req.body.username],
        function (err, users) {
            if (err) {
                res.sendStatus(500)
                console.error(err)
            } else if (users.length == 0) {
                res.status(401).json({ message: 'username or password is incorrect' })
            } else {
                bcrypt.compare(req.body.password, users[0].password,
                    function (err, isLogin) {
                        if (isLogin) {
                            const token = jwt.sign({ username: users[0].username }, secret, { expiresIn: '10m' })
                            res.status(200).json({ message: 'login successfully ', token })
                            next()
                        } else {
                            res.status(401).json({ message: 'username or password is incorrect' })
                        }
                    }
                );
            }
        }
    );
})

const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (authHeader) {
        const token = authHeader;
        jwt.verify(token, secret, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

const customers = [
    { id: 1, name: "John Wick", email: "jwick@example.com", phone: "123-456-7890" },
    { id: 2, name: "Post Malone", email: "post_m@example.com", phone: "586-256-9878" }
]

app.get('/customers', authenticateJWT, function (req, res, next) {
    res.status(200).json(customers)
})

app.listen(5000, function () {
    console.log('Server listening on port 5000')
})