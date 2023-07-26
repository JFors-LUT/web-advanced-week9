const mongoose = require("mongoose");

const Schema = mongoose.Schema

let userSchema = new Schema({
  username: String,
  password: String,
});

const User = mongoose.model('User', userSchema);

async function findUserByUsername(username) {
  try {
    const user = await User.findOne({ username }); 
    return user; 
  } catch (error) {
    console.error("Error finding user:", error);
    return null;
  }
}

async function addUser(user) {
  console.log(user)
  try {
    const newUser = new User(user);
    await newUser.save();
    console.log("User added successfully:", newUser);
    return newUser;
  } catch (error) {
    console.error("Error adding user:", error);
    return null;
  }
}

module.exports = {User, findUserByUsername, addUser}