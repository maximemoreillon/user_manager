// modules
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors')
const neo4j = require('neo4j-driver');
const bcrypt = require('bcrypt')
const dotenv = require('dotenv');
const authentication_middleware = require('@moreillon/authentication_middleware')

dotenv.config();

const driver = neo4j.driver(
  process.env.NEO4J_URL,
  neo4j.auth.basic(
    process.env.NEO4J_USERNAME,
    process.env.NEO4J_PASSWORD
  )
)

// Config
var app_port = 80
if(process.env.APP_PORT) app_port=process.env.APP_PORT

authentication_middleware.authentication_api_url = `${process.env.AUTHENTIATION_API_URL}/decode_jwt`

// Express configuration
const app = express()
app.use(bodyParser.json())
app.use(cors())
app.use(authentication_middleware.middleware)

app.get('/', (req, res) => {
  res.send(`
    User management API, Maxime MOREILLON <br>
    ${process.env.NEO4J_URL}
    `)
})

app.get('/all_users', (req, res) => {
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    RETURN user
    `, {})
  .then(result => {
    res.send(result.records)
  })
  .catch(error => { res.status(500).send(`Error getting users: ${error}`) })
  .finally(() => session.close())
})

app.get('/user', (req, res) => {
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({user_id})
    RETURN user
    `, {
    user_id: req.query.user_id
  })
  .then(result => {
    res.send(result.records[0].get('user'))
  })
  .catch(error => { res.status(500).send(`Error getting users: ${error}`) })
  .finally(() => session.close())
})

app.post('/create_user', (req, res) => {

  // Input sanitation
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
      res.send(result.records[0].get('user'))
    })
    .catch(error => { res.status(500).send(`Error creating user: ${error}`) })
    .finally(() => session.close())
  })

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
    if(result.records.length === 0 ) return res.status(400).send(`User deletion failed`)
    res.send("User deleted successfully")
  })
  .catch(error => { res.status(500).send(`Error deleting user: ${error}`) })
  .finally(() => session.close())
})




app.post('/change_display_name', (req, res) => {
  // Todo: allow admins to change display names
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({current_user_id})
    SET user.display_name={display_name}
    RETURN user
    `, {
    current_user_id: res.locals.user.identity.low,
    display_name: req.body.display_name,
  })
  .then(result => {
    if(result.records.length === 0 ) return res.status(400).send(`Setting display name failed`)
    res.send(user)
  })
  .catch(error => { res.status(500).send(`Error changing display name for user: ${error}`) })
  .finally(() => session.close())
})

app.post('/change_avatar_src', (req, res) => {
  // Todo: allow admins to change display names
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({current_user_id})
    SET user.avatar_src={avatar_src}
    RETURN user
    `, {
    current_user_id: res.locals.user.identity.low,
    avatar_src: req.body.avatar_src,
  })
  .then(result => {
    if(result.records.length === 0 ) return res.status(400).send(`Setting avatar failed`)
    res.send(user)
  })
  .catch(error => { res.status(500).send(`Error changing avatar for user: ${error}`) })
  .finally(() => session.close())
})

// Start server
app.listen(app_port, () => {
  console.log(`User manager listening on *:${app_port}`);
});
