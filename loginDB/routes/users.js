var express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const mongoose = require("mongoose");
const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');

const User = require('../models/Users');
var router = express.Router();

const SECRET = process.env.SECRET || 'secret';

//configure for passport
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
  secretOrKey: SECRET,
};

passport.use(
  new JwtStrategy(jwtOptions, async (payload, done) => {
    try {
      const user = await User.findOne({ username: payload.username });
      if (!user) {
        return done(null, false);
      }

      return done(null, user);
    } catch (error) {
      return done(error, false);
    }
  })
);

router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.get('/api/private', passport.authenticate('jwt', { session: false }), (req, res) => {
  console.log(req.body)
  return res.status(200).json({ username: req.user.username });
});

const strongPasswordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~`!@#$%^&*()-_+={}[\]|\\;:"<>,./?]).{8,}$/;
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

router.post('/api/user/register', async (req, res, next) => {
  const username = req.body.username; 
  const password = req.body.password; 

  try {
    const userExists = await User.findOne({ username });

    if (userExists) {
      return res.status(403).json('Username already in use.');
    }

    if (!emailRegex.test(username)) {
      return res.status(400).json('Invalid email format.');
    }

    if (!strongPasswordRegex.test(password)) {
      return res.status(400).json('Invalid password format. Password should include at least one lowercase letter, one uppercase letter, one number, one symbol and 8 characters');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
    });

    await newUser.save();

    res.status(201).json('ok');
  } catch (error) {
    console.error(error);
    return res.status(500).json('error');
  }
});


router.post('/api/user/login', async (req, res) => {

  const username = req.body.username; 
  const password = req.body.password; 
  

  try {
    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json('Invalid username');
    };

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json('Invalid credentials');
    };
    const payload = {
      username: user.username,
    };

    jwt.sign(payload, SECRET, (err, token) => {
      if (err) {
        console.error(err);
        return res.status(500).json('Internal server error');
      }

      return res.status(200).json({ token });
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json(error);
  }
});

module.exports = router;
