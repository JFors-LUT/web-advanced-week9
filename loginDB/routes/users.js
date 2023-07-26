var express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const mongoose = require("mongoose");
const User = require('../models/Users');
var router = express.Router();

const SECRET = process.env.SECRET || 'secret';


router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

/*
router.post('/api/user/register', async (req, res) => {
  const { username, password } = req.body;
  console.log(req.body);
  const userFound = await userModel.findUserByUsername(username)
  if (userFound) {
    return res.status(403).json({email:'Email already in use.'});
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const userId = uuidv4();

  const newUser = { username, password: hashedPassword };
  userModel.addUser(newUser);

  res.status(201).json('User registered');
});
*/

/*
router.post('/api/user/register', (req, res, next) => {
  
  const user = req.body.username;
  const password  = req.body.password;

  User.findOne({ username:user }) 
    .exec()
    .then((userFind) => {
      if (!userFind) {
        return User.create({
          username: user,
          password: password,
        });
      } else {
        return Promise.reject('User already in database.');
      }
    })
    .then((user) => {
      res.status(201).json(user);
    })
    .catch((error) => {
      if (error === 'User already in database.') {
        return res.status(403).json({email:'Email already in use.'});;
      } else {
        return res.status(500).json({error});
      }
    });
});
*/
router.post('/api/user/register', async (req, res) => {
  const { username, password } = req.body;

  try {
    const userExists = await User.findOne({ username });

    if (userExists) {
      return res.status(403).json('Username already in use.');
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      username,
      password: hashedPassword,
    });

   await newUser.save();

    res.status(201).json("ok");
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
    console.log(user)
    if (!user) {
      return res.status(401).json('Invalid username');
    };

    const passwordMatch = await bcrypt.compare(password, user.password);
    console.log(passwordMatch)
    if (!passwordMatch) {
      return res.status(401).json('Invalid credentials');
    };

    const payload = {
      email: user.email,
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


/*
router.post('/api/user/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await userModel.findUserByUsername(username);

  if (!user) {
    return res.status(401).json('Invalid credentials');
  }

  const passwordMatch = await bcrypt.compare(password, user.password);

  if (!passwordMatch) {
    return res.status(401).json('Invalid credentials');
  }

  const token = jwt.sign({ username: user.username }, 'secret');
  res.status(200).json({ token });
});

  const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
  
    if (!token) {
      return res.status(401).json('Unauthorized');
    }
  
    jwt.verify(token, 'secret', (err, decodedToken) => {
      if (err) {
        return res.status(401).json('Invalid token');
      }
  
      req.userId = decodedToken.userId;
      next();
    });
  };
*/


module.exports = router;
