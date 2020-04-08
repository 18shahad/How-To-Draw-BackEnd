var mongoose = require('mongoose');

var Favourite = mongoose.model('Favourite',{
    dir :{
        type : String
        },
    type :{
        type : String
            },
    user_name :{
        type : String,
        required : true
        }
});


module.exports = {Favourite};
