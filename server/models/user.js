const mongoose = require('mongoose');
const validator = require('validator');
const JWT = require('jsonwebtoken');
const _ = require('lodash');
const bcryptjs = require('bcryptjs');

var UserSchema = new mongoose.Schema({
    name :{
        type : String,
        trim : true
    },
    user_name :{
        type : String,
        required : true,
        trim : true,
        minlength : 1,
        uniqe : true
    },
    gender :{
        type : String
        },
    birthday :{
        type : String
    },
    password : {
        type : String,
        minlength: 6,
        required : true 
    },
    tokens: [{
        access: {
            type : String,
            required : true
        },
        token: {
            type : String,
            required : true
        }
    }]
});

// To return custumized object only id and user name
UserSchema.methods.toJSON = function () {
    var user = this;
    var userObject = user.toObject();

    return _.pick(userObject,['_id','user_name']);
};

// For token
UserSchema.methods.generateAuthToken = function () {
    var user = this;
    var access = 'auth';
    var token = JWT.sign({_id: user._id.toHexString(),access},'abc123').toString();

    user.tokens.push({access,token});
    return user.save().then(()=>{
        return token;
    });
};

// For token "select user by token"
UserSchema.statics.findByToken = function(token){
    var User = this;
    var decoded;
    try{
         decoded = JWT.verify(token , 'abc123');
    } catch (e){
        return Promise.reject();
    }

   return User.findOne({
        '_id' : decoded._id,
        'tokens.token': token,
        'tokens.access': 'auth'
    });
};

// For hashing passwords by bcryptjs
UserSchema.pre('save',function (next) {
    var user = this;
    if(user.isModified('password')){
        bcryptjs.genSalt(10,(err,salt)=>{
            bcryptjs.hash(user.password,salt,(err,hashedPassword)=>{
                user.password = hashedPassword;
                next();
            });
        });
    } else {
        next();
    }
    
});

// decrypt for password
UserSchema.statics.findByCredentials = function (user_name,password) {
    var User = this;
    
    return User.findOne({user_name}).then((user)=>{
        if(!user){
            return new Promise.reject();
        }
        return new Promise((resolve,reject)=>{
            //To compare the entered password with the one in the DB
            bcryptjs.compare(password,user.password,(err,res)=>{
                if(res){
                    resolve(user);
                }else{
                    reject();
                }
            });
        });
        
    });
};

// For log out
UserSchema.methods.removeToken = function (token) {
    var user = this;
    return user.update({
        $pull : {
            tokens : {token}
        }
        
    });
};




var User = mongoose.model('User',UserSchema);


module.exports = {User};