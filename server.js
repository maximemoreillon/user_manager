// modules
const process = require('process');
const path = require('path');
const http = require('http');
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors')
const history = require('connect-history-api-fallback');
const bcrypt = require('bcrypt');
const authorization_middleware = require('@moreillon/authorization_middleware')
const neo4j = require('neo4j-driver');

// custom modules
const secrets = require('./secrets');

const driver = neo4j.driver(
  secrets.neo4j.url,
  neo4j.auth.basic(secrets.neo4j.username, secrets.neo4j.password)
)

// Config
const app_port = 7045;
const saltRounds = 10;

authorization_middleware.secret = secrets.jwt_secret


// Express configuration
const app = express()
app.use(bodyParser.json())
app.use(history())
app.use(express.static(path.join(__dirname, 'dist')))
app.use(cors())
app.use(authorization_middleware.middleware)

app.post('/create_user', (req, res) => {

  // Input Check
  if(!('user' in req.body)) return res.status(400).send(`User missing from body`)
  if(!('properties' in req.body.user)) return res.status(400).send(`User properties missing from user`)
  if(!('password_plain' in req.body.user.properties && 'username' in req.body.user.properties)) {
    return res.status(400).send(`Username or password missing`)
  }

  bcrypt.hash(req.body.user.properties.password_plain, 10, (err, hash) => {
    if(err) return res.status(500).send(`Error hashing password: ${err}`)

    // do not store the plain text password
    delete req.body.user.properties.password_plain

    // Store the hashed version instead
    req.body.user.properties.password_hashed = hash

    var session = driver.session()
    session
    .run(`
      // create the user node
      CREATE (user:User)

      // Set properties
      SET user = {user}.properties

      // Return the user
      RETURN user
      `, {
      user: req.body.user
    })
    .then(result => {
      session.close()
      res.send(result.records[0].get('user'))
    })
    .catch(error => { res.status(500).send(`Error creating user: ${error}`) })
  });


})


app.post('/delete_user', (req, res) => {
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)

    // prevent user moreillon from being deleted
    WHERE id(user) = toInt({user_id}) AND NOT user.username = 'moreillon'

    // Delete
    DETACH DELETE user
    RETURN 'success'
    `, {
    user_id: req.body.user_id
  })
  .then(result => {
    session.close()
    if(result.records.length === 0 ) return res.status(400).send(`User deletion failed`)
    res.send("User deleted successfully")
  })
  .catch(error => { res.status(500).send(`Error deleting user: ${error}`) })
})

app.post('/get_user_list', (req, res) => {
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    RETURN user
    `, {
    user: req.body.user
  })
  .then(result => {
    session.close()
    res.send(result.records)
  })
  .catch(error => { res.status(500).send(`Error getting users: ${error}`) })
})

app.post('/get_user', (req, res) => {
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({user_id})
    RETURN user
    `, {
    user_id: req.body.user_id
  })
  .then(result => {
    session.close()
    res.send(result.records[0].get('user'))
  })
  .catch(error => { res.status(500).send(`Error getting users: ${error}`) })
})


// Start server
app.listen(app_port, () => {
  console.log(`User manager listening on *:${app_port}`);
});
