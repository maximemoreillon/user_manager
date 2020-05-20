// modules
const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const neo4j = require('neo4j-driver')
const bcrypt = require('bcrypt')
const dotenv = require('dotenv')

const auth = require('@moreillon/authentication_middleware')

dotenv.config();

const driver = neo4j.driver(
  process.env.NEO4J_URL,
  neo4j.auth.basic(
    process.env.NEO4J_USERNAME,
    process.env.NEO4J_PASSWORD
  )
)

// Port configuration
var app_port = 80
if(process.env.APP_PORT) app_port=process.env.APP_PORT


function self_only_unless_admin(req, res){
  let current_user_id = res.locals.user.identity.low
  let current_user_is_admin = !!res.locals.user.properties.isAdmin

  let user_id = undefined

  // check if user_id provided in the request
  if(('user_id' in req.body)) user_id = req.body.user_id
  else if(('user_id' in req.query)) user_id = req.query.user_id

  if(user_id) {
    if(user_id !== current_user_id) {
      if(current_user_is_admin) return user_id
      else throw 'Unauthorized to modify another user'
    }
    // If user_id is that of self, the allow
    else return user_id
  }
  // If user_id was not specified, just return the current user id
  else return current_user_id

}

function admin_only_and_not_oneself(req, res){

  let current_user_id = res.locals.user.identity.low

  if(!res.locals.user.properties.isAdmin) throw 'Only administrators can perform this operation'

  let user_id = undefined

  // check if user_id provided in the request
  if(('user_id' in req.body)) user_id = req.body.user_id
  else if(('user_id' in req.query)) user_id = req.query.user_id

  if(user_id) {
    if(user_id !== current_user_id) return user_id
    else throw 'Cannot perform operation on oneself'
  }
  else throw 'User ID not specified'

}

// Express configuration
const app = express()
app.use(bodyParser.json())
app.use(cors())
app.use(auth.authenticate)

app.get('/', (req, res) => {
  res.send(`User management API, Maxime MOREILLON`)
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

  let user_id = undefined
  if(('user_id' in req.query)) user_id = req.query.user_id
  else user_id = res.locals.user.identity.low


  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({user_id})
    RETURN user
    `, {
    user_id: user_id
  })
  .then(result => {
    res.send(result.records[0].get('user'))
  })
  .catch(error => {
    console.log(error)
    res.status(500).send(`Error getting users: ${error}`)
  })
  .finally(() => session.close())
})



app.post('/create_user', (req, res) => {

  // Input sanitation
  if(!('user' in req.body)) return res.status(400).send(`User missing from body`)
  if(!('properties' in req.body.user)) return res.status(400).send(`User properties missing from user`)
  if(!('password_plain' in req.body.user.properties)) return res.status(400).send(`Missing password`)
  if(!('username' in req.body.user.properties)) return res.status(400).send(`Username or password missing`)

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
  // Todo: make this a DELETE request
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


app.post('/update_display_name', (req, res) => {
  // Todo: allow admins to change display names

  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({user_id})
    SET user.display_name={display_name}
    RETURN user
    `, {
    user_id: self_only_unless_admin(req, res),
    display_name: req.body.display_name,
  })
  .then(result => {
    if(result.records.length === 0 ) return res.status(400).send(`Setting display name failed`)
    res.send(result.records[0].get('user'))
  })
  .catch(error => { res.status(500).send(`Error changing display name for user: ${error}`) })
  .finally(() => session.close())
})

app.post('/update_last_name', (req, res) => {
  // Todo: allow admins to change display names
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({user_id})
    SET user.last_name={last_name}
    RETURN user
    `, {
    user_id: self_only_unless_admin(req, res),
    last_name: req.body.last_name,
  })
  .then(result => {
    if(result.records.length === 0 ) return res.status(400).send(`Setting display name failed`)
    res.send(result.records[0].get('user'))
  })
  .catch(error => { res.status(500).send(`Error changing display name for user: ${error}`) })
  .finally(() => session.close())
})

app.post('/update_first_name', (req, res) => {
  // Todo: allow admins to change display names
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({user_id})
    SET user.first_name={first_name}
    RETURN user
    `, {
    user_id: self_only_unless_admin(req, res),
    first_name: req.body.first_name,
  })
  .then(result => {
    if(result.records.length === 0 ) return res.status(400).send(`Setting display name failed`)
    res.send(result.records[0].get('user'))
  })
  .catch(error => { res.status(500).send(`Error changing display name for user: ${error}`) })
  .finally(() => session.close())
})

app.post('/update_password', auth.authenticate, (req, res) => {

  // Input sanitation
  if(!('new_password' in req.body)) return res.status(400).send(`Password missing from body`)

  // Hash the provided password
  bcrypt.hash(req.body.new_password, 10, (err, hash) => {
    if(err) return res.status(500).send(`Error hashing password: ${err}`)

    const session = driver.session();
    session
    .run(`
      // Find the user using ID
      MATCH (user:User)
      WHERE id(user) = toInt({user_id})

      // Set the new password
      SET user.password_hashed={new_password_hashed}

      // Return user once done
      RETURN user
      `, {
        user_id: self_only_unless_admin(req, res),
        new_password_hashed: hash
      })
      .then(result => { res.send(result.records) })
      .catch(error => res.status(400).send(`Error accessing DB: ${error}`))
      .finally( () => session.close())
  })
})

app.post('/update_avatar', (req, res) => {
  // Todo: allow admins to change display names
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({user_id})
    SET user.avatar_src={avatar_src}
    RETURN user
    `, {
    user_id: self_only_unless_admin(req, res),
    avatar_src: req.body.avatar_src,
  })
  .then(result => {
    if(result.records.length === 0 ) return res.status(400).send(`Setting avatar failed`)
    res.send(result.records[0].get('user'))
  })
  .catch(error => { res.status(500).send(`Error changing avatar for user: ${error}`) })
  .finally(() => session.close())
})

app.post('/update_administrator_rights', (req, res) => {
  // Todo: allow admins to change display names
  // Todo: admin only!
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({user_id})
    SET user.isAdmin={isAdmin}
    RETURN user
    `, {
    user_id: admin_only_and_not_oneself(req, res),
    isAdmin: req.body.isAdmin,
  })
  .then(result => {
    if(result.records.length === 0 ) return res.status(400).send(`Setting administrator rights failed`)
    res.send(result.records[0].get('user'))
  })
  .catch(error => { res.status(500).send(`Error updating administrator rights for user: ${error}`) })
  .finally(() => session.close())
})

// Start server
app.listen(app_port, () => {
  console.log(`User manager listening on *:${app_port}`);
});
