var express = require('express');
var router = express.Router();
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const userModel = require('../models/Users');

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

router.post('/api/user/register', async (req, res) => {
  const { username, password } = req.body;
  console.log(req.body);

  if (await userModel.findUserByUsername(username)) {
    return res.status(403).json({email:'Email already in use.'});
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const userId = uuidv4();

  const newUser = { username, password: hashedPassword };
  userModel.addUser(newUser);

  res.status(201).json('User registered');
});

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



module.exports = router;
