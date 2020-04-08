var mongoose = require('mongoose');

var Completed = mongoose.model('Completed',{
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


module.exports = {Completed};
