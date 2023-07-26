var express = require('express');
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const mongoose = require("mongoose");
const User = require('../models/Users');
var router = express.Router();


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

router.post('/api/user/register', (req, res, next) => {
  const { user, pw } = req.body;
  User.findOne({ username:user }) 
    .exec()
    .then((user) => {
      if (!user) {
        return User.create({
          username: user,
          password: pw,
        });
      } else {
        return Promise.reject('User already in database.');
      }
    })
    .then((recipe) => {
      res.status(201).json('User registered');
    })
    .catch((error) => {
      if (error === 'User already in database.') {
        return res.status(403).json({email:'Email already in use.'});;
      } else {
        return res.status(500).json({error});
      }
    });
});

router.post('/api/user/login', async (req, res) => {
  const { username, password } = req.body;
  const userFind = await User.findOne({ username }); 

  if (!userFind) {
    return res.status(401).json('Invalid credentials');
  }

  const passwordMatch = bcrypt.compare(password, userFind.password);

  if (!passwordMatch) {
    return res.status(401).json('Invalid credentials');
  }

  const token = jwt.sign({ username: userFind.username }, 'secret');
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
