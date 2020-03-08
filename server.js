const express = require('express');
const logger = require('morgan')
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")

const app = express();

const PORT = process.env.PORT || 8080;

// stored in DB
const users = []

// MIDDLEWARE
app.use(express.urlencoded({ extended: true }));
app.use(express.json())
app.use(logger("dev"));

// routes

/**
 * Get all users
 */
app.get('/users', (req, res)=>{
  res.json(users)
});

/**
 * Create user
 */
app.post('/user/create', async (req, res)=>{
  const {name, password} = req.body;

  try{ 
    const hashedPassword = await bcrypt.hash(password, 10)
    users.push({name, hashedPassword})
    res.status(201).send({success:true})

  } catch(e){
    console.log(`Error encrypting password`, e)
    res.status(500).send("Error encrypting password. Please try again.")
  }

});


/**
 * Login user
 */
app.post("/user/login", async ({body:{name, password}}, res)=>{
  console.log('name, password', name, password)

  // check db to see if user exists
  const user = users.find(user=>user.name === name)
  if(!user) return res.status(400).send("Check credentials and try again");

  try{
    // compare submitted password and hashed password of found user
    if(await bcrypt.compare(password, user.hashedPassword)){
      // user logged in
      res.send({success:true})
    } else{
      res.status(400).send("Check credentials and try again")
    }
  }catch(e){
    console.log('e - ', e)
    res.status(500).send("Please try again.")
  }


})


app.listen(PORT, ()=>{
  console.log(`Listening on PORT ${PORT}`)
});