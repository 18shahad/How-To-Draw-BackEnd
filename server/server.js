const express = require('express');
const bodyParser = require('body-parser');
const _ = require('lodash');// library "Utility tool"
const cors = require('cors');


var {mongoose} = require('./db/mongoose');
var {User} = require('./models/user');
var {Favourite} = require('./models/favourite');
var {Completed} = require('./models/completed');

var app = express();

const port = process.env.DRAWPORT || 3500;

// To make the request is in json
app.use(bodyParser.json());
const corsOptions = {
    exposedHeaders: 'x-auth',
  };
app.use((req, res, next) => {
    res.set('Access-Control-Allow-Origin', '*')
    next()
  })
  app.use(cors(corsOptions));

app.post('/users',(req,res)=>{
    var body = _.pick(req.body,["name","user_name","gender","birthday","password"]);
    var user = new User(body);
    user.save().then((user)=>{
       return user.generateAuthToken();
    }).then((token)=>{
        res.header('x-auth',token).send(user);
    })
    .catch((er)=>{
        res.status(400).send(er);
    });

});

app.post('/favourites',(req,res)=>{
    var body = _.pick(req.body,["dir","type","user_name"]);
    var favourite = new Favourite(body);
    favourite.save().then((favourite)=>{
        res.status(200).send(favourite);
    })
    .catch((er)=>{
        res.status(400).send(er);
    });

});

app.get('/favourites/:user_name',(req,res)=>{
    Favourite.find({user_name : req.params.user_name}).then(favourites =>{
        if(favourites){
            res.status(200).send(favourites);
        }else{
            res.status(404).send("there is no favourites saved");
        }
    })
    .catch((er)=>{
        res.status(400).send(er);
    });

});

app.post('/completed',(req,res)=>{
    var body = _.pick(req.body,["dir","type","user_name"]);
    var completed = new Completed(body);
    completed.save().then((completed)=>{
        res.status(200).send(completed);
    })
    .catch((er)=>{
        res.status(400).send(er);
    });

});

app.get('/completed/:user_name',(req,res)=>{
    Completed.find({user_name : req.params.user_name}).then(completed =>{
        if(completed){
            res.status(200).send(completed);
        }else{
            res.status(404).send("there is no completed draws saved");
        }
    })
    .catch((er)=>{
        res.status(400).send(er);
    });

});


app.post('/users/login',(req,res)=>{
    var body = _.pick(req.body,['user_name','password']);

    User.findByCredentials(body.user_name,body.password).then((user)=>{
        res.send(user);
    }).catch((er)=>{
        res.status(400).send(er);
    });
});


app.listen(port,()=>{
    console.log(`the server is on at port ${port}`);
});




 