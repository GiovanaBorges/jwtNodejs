require("dotenv").config()
const express = require('express');
const app = express()
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

//config json
app.use(express.json())

const User = require('./model/UserModel')

//private Route 
app.get('/user/:id',checkToken,async(req,res)=>{
    const id = req.params.id

    const user = await User.findById(id,'-password')
    if(!user){
        return res.status(404).json({msg:"User not found"})
    }

    res.status(200).json({ user });
})

function checkToken(req,res,next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        res.status(401).json({msg:"Not authorized"})
    }

    try{
        const secret = process.env.SECRET
        jwt.verify(token,secret)
        next()
    }catch(err){
        console.log(err)
        res.status(401).json({msg:"server errror"})
    }
}

//route for authenticate user
app.post('/auth/login', async(req,res)=>{
    const {email,password} = req.body

    if(!email){
        return res.status(422).json({msg:"The email must be provided"})
    }
    if(!password){
        return res.status(422).json({msg:"The password must be provided"})
    }

    const userExists = await User.findOne({email:email})
    if(!userExists){
        return res.status(404).json({msg:"User not found"})
    }

    const checkPassword = await bcrypt.compare(password, userExists.password)
    if(!checkPassword){
        return res.status(422).json({msg:"Password Invalid"})
    }

    try{
        const secret = process.env.SECRET
        const token = jwt.sign({id:userExists._id},secret)
        res.status(200).json({msg:`Autenticao realizada com sucesso ,Token : ${token} - user: ${userExists._id}`})
    }catch(err){
        console.log(err)
        res.status(422).json({msg:"Server error"})
    }
})

//route for create user
app.post('/auth/register', async (req,res)=>{
    const {name,email,pass,confirmPass} = req.body

    if(!name){
        return res.status(422).json({msg:"The name must be provided"})
    }
    if(!email){
        return res.status(422).json({msg:"The email must be provided"})
    }
    if(!pass){
        return res.status(422).json({msg:"The password must be provided"})
    }
    if(!confirmPass){
        return res.status(422).json({msg:"The password confirm must be provided"})
    }

    if(confirmPass !== pass){
        return res.status(422).json({msg:"The password must be equal"})
    }

    //check if the user exists 
    const verifyUserExists = await User.findOne({email:email})
    if(verifyUserExists){
        return res.status(422).json({msg:"This user already exists"})
    }

    //create password 
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(pass,salt)

    const user = new User({
        name
        ,email
        ,passwordHash
    })

    try{
        await user.save()
        res.status(201).json({msg:'user created successfully'})
    }catch(err){
        console.log(err)
        res.status(500).json({msg:'occurs a error on the server , please try again'})
    }
})

//credetials 
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASS

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPass}@cluster0.qw07qgu.mongodb.net/?retryWrites=true&w=majority`
    )
    .then(()=>{
        app.listen(3000)
        console.log("Conectou ao banco")
    })
    .catch((error) =>{console.log(error)})

