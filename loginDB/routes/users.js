var express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const mongoose = require("mongoose");
const passport = require('passport');
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt');
const { check, validationResult } = require('express-validator');



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
      const user = await User.findOne({ email : payload.email  });
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
  return res.status(200).json({ email : req.user.email });
});

router.post('/api/user/register', [
  //check("email").matches(/@/).withMessage('Illegal email format'),
  check('password')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/[a-z]/).withMessage('Password must contain at least one lowercase letter')
    .matches(/[A-Z]/).withMessage('Password must contain at least one uppercase letter')
    .matches(/\d/).withMessage('Password must contain at least one number')
    .matches(/[~`!@#$%^&*()-_+={}[\]|\\;:"<>,./?]/).withMessage('Password must contain at least one symbol: ~`!@#$%^&*()-_+={}[]|\\;:"<>,./?')
], async (req, res) => {

  const errors = validationResult(req);

  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  console.log(req.body)
  const email  = req.body.email ; 
  const password = req.body.password; 

  try {
    const userExists = await User.findOne({ email  });

    if (userExists) {
      return res.status(403).json('Username already in use.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    User.create({
      email,
      password: hashedPassword,
    });


    res.status(200).json('ok');
  } catch (error) {
    console.error(error);
    return res.status(500).json('error');
  }
});


router.post('/api/user/login', async (req, res) => {

  const email  = req.body.email ; 
  const password = req.body.password; 
  

  try {
    const user = await User.findOne({ email  });
    if (!user) {
      return res.status(401).json('Invalid username');
    };

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json('Invalid credentials');
    };
    const payload = {
      email : user.email ,
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
