const mongoose = require("mongoose");


const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
});

const Users = mongoose.model('Users', userSchema);

async function findUserByUsername(username) {
  try {
    const user = await Users.findOne({ username }); 
    return user; 
  } catch (error) {
    console.error("Error finding user:", error);
    return null;
  }
}

async function addUser(user) {
  console.log(user)
  try {
    const newUser = new Users(user);
    await newUser.save();
    console.log("User added successfully:", newUser);
    return newUser;
  } catch (error) {
    console.error("Error adding user:", error);
    return null;
  }
}

module.exports = {Users, findUserByUsername, addUser}