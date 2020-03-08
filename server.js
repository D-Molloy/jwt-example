const express = require('express');
const logger = require('morgan');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 8080;

// stored in DB
const users = [];
const posts = [
  {
    name: 'Denis',
    title: 'Post 1'
  },
  {
    name: 'Amanda',
    title: 'Post 2'
  }
];
let refreshTokens = [];

// MIDDLEWARE
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(logger('dev'));

// ensure the jwt is present and valid
// TODO: Move to auth route
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // if the authHeader doesn't exist, token will be undefined
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Invalid token.' });

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token.' });
    // valid token
    req.user = user;
    next();
  });
};

const generateAccessToken = user => {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: 1000 * 60 * 60
  });
};

// routes

/**
 * Get all users
 */
app.get('/users', authenticateToken, (req, res) => {
  res.json(users);
});

/**
 * Get all posts for the logged in user
 */
app.get('/posts', authenticateToken, (req, res) => {
  res.json(posts.filter(post => post.name === req.user.name));
});

/**
 * Create user
 */
// TODO: Move to auth route
app.post('/user/create', async (req, res) => {
  const { name, password } = req.body;
  //TODO: check DB to see if user already exists

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    users.push({ name, hashedPassword });
    res.status(201).send({ success: true });
  } catch (e) {
    console.log(`Error encrypting password`, e);
    res.status(500).send('Error encrypting password. Please try again.');
  }
});

/**
 * Login user
 */
// TODO: Move to auth route
app.post('/user/login', async ({ body: { name, password } }, res) => {
  // check db to see if user exists
  const user = users.find(user => user.name === name);
  if (!user) return res.status(400).send('Check credentials and try again');

  try {
    // compare submitted password and hashed password of found user
    if (await bcrypt.compare(password, user.hashedPassword)) {
      // user logged in
      // Create JWT
      const user = {
        name
      };

      const accessToken = generateAccessToken(user);
      const refreshToken = jwt.sign(user, process.env.REFRESH_TOKEN_SECRET);
      // save refreshtokens in DB
      refreshTokens.push(refreshToken);

      // send the JWT to the user
      res.send({ accessToken, refreshToken });
    } else {
      res.status(400).send('Check credentials and try again');
    }
  } catch (e) {
    console.log('e - ', e);
    res.status(500).send('Please try again.');
  }
});

// to get a new accessToken if the old one has expired
// called manually from the client if the user's token is expired
app.post('/token', (req, res) => {
  const refreshToken = req.body.token;
  // refreshToken should be saved in DB
  if (!refreshToken) return res.status(401);
  if (!refreshTokens.includes(refreshToken)) return res.status(403);
  jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.status(403);
    const accessToken = generateAccessToken({ name: user.name });
    res.json({ accessToken });
  });
});

// remove the access token
app.delete('/logout', (req, res) => {
  if(!req.body.token) return res.sendStatus(400)
  // remove from DB
  refreshTokens = refreshTokens.filter(token => token !== req.body.token);
  res.sendStatus(204);
});

app.listen(PORT, () => {
  console.log(`Listening on PORT ${PORT}`);
});
