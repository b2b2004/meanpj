const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const config = require('../config/database');
// User Schema

const UserSchema = mongoose.Schema({
name: {
type: String,
required: true
},
email: {
type: String,
required: true
},
username: {
type: String,
required: true
},
password: {
type: String,
required: true
},
cert: {
    type: String,
    required: false,
    },
})

const User = mongoose.model('User', UserSchema);

User.getUserById = function(id, callback){
    User.findById(id, callback);
    }

User.getUserByUsername = function(username, callback){
    const query = {username: username};
    User.findOne(query, callback);
}
    
User.addUser = function(newUser, callback){
    bcrypt.genSalt(10, (err, salt) => {
    bcrypt.hash(newUser.password, salt, (err, hash) => {
    if(err) throw err;
    newUser.password = hash;
    newUser.save(callback);
    });
    });
}

User.comparePassword = function(candidatePassword, hash, callback){
    bcrypt.compare(candidatePassword, hash, (err, isMatch)=>{
    if(err) throw err;
    callback(null, isMatch);
    });
}
User.getAll = function (callback) {
    User.find(callback);
    };


    User.saveCert = function (username, cert, callback) {
        const query = { username: username };
        const update = { cert: cert };
        User.findOneAndUpdate(
        query,
        update,
        { new: true, useFindAndModify: false },
        callback
        );
        };
        
module.exports = User;
    