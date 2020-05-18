const router = require("express").Router();
const bcryptjs = require("bcryptjs");

const Users = require("../users/users-model.js");
const {isValid} = require("../users/users-service.js")

router.post("/register", (req, res)=>{
    const credentials = req.body

    if(isValid(credentials)){
        const rounds = process.env.BCRYPT_ROUNDS || 8;
        const hash = bcryptjs.hashSync(credentials.password, rounds);
        credentials.password = hash;
        Users.add(credentials)
        .then(user=>{
            res.status(201).json({data: user})
        })
        .catch(err=>{
            console.log(err)
            res.status(500).json({error: "Could not create user"})
        })
    }
    else{
        res.status(400).json({error: "Username and Password are required and should be alphanumeric"})
    }
})

router.post("/login", (req, res)=>{
    const {username, password} = req.body
    if(isValid(req.body)){
        const rounds = process.env.BCRYPT_ROUNDS || 8;
        Users.findBy({username: username}).first()
        .then(user=>{
            if(user && bcryptjs.compareSync(password, user.password)){
                req.session.loggedIn = true;
                req.session.user = user;
                res.status(200).json({success: "Logged in"})
            }
            else{
                res.status(401).json({error: "Incorrect username or password"})
            }
        })
        .catch(err=>{
            console.log(err)
            res.status(500).json({error: "Unable to log in"})
        })
    }
})

router.get("/logout", (req, res)=>{
    if(req.session){
        req.session.destroy(err=>{
            if(err){
                console.log(err);
                res.status(500).json({error: "Internal Server Error"})
            }
            else{
                res.status(204).end();
            }
        });
    }
    else{
        res.status(204).end();
    }
})

module.exports = router;