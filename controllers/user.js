const driver = require('../neo4j_driver.js')
const bcrypt = require('bcrypt')
const dotenv = require('dotenv')

dotenv.config()

function self_only_unless_admin(req, res){

  // Todo: error message if user is not admin and tries to edit another user

  const current_user_is_admin = !!res.locals.user.properties.isAdmin

  if(current_user_is_admin) {
    return req.body.user_id
      ?? req.query.user_id
      ?? req.params.user_id
      ?? res.locals.user.identity.low
      ?? res.locals.user.identity
  }
  else {
    return res.locals.user.identity.low
      ?? res.locals.user.identity
  }

}

function get_current_user_id(res){
  return res.locals.user.identity.low
    ?? res.locals.user.identity
}

function get_user_id_from_query_or_own(req, res){
  let user_id = req.params.user_id
    ?? req.query.user_id
    ?? req.query.id
    ?? res.locals.user.identity.low
    ?? res.locals.user.identity

  if(user_id === 'self') user_id = get_current_user_id(res)

  return user_id
}



exports.get_user = (req, res) => {

  const user_id = get_user_id_from_query_or_own(req, res)

  const session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInteger($user_id)
    RETURN user
    `, {
    user_id
  })
  .then(result => {
    res.send(result.records[0].get('user'))
  })
  .catch(error => {
    console.log(error)
    res.status(500).send(`Error getting users: ${error}`)
  })
  .finally(() => session.close())
}

exports.create_user = (req, res) => {

  // TODO: Prevent registering a user if identifier already exists

  // TODO: Password confirm maybe?

  if(!res.locals.user.properties.isAdmin){
    return res.status(403).send(`Only administrators can create users`)
  }


  // Input sanitation
  if(!('user' in req.body)) return res.status(400).send(`User missing from body`)
  if(!('properties' in req.body.user)) return res.status(400).send(`User properties missing from user`)
  if(!('password_plain' in req.body.user.properties)) return res.status(400).send(`Missing password`)
  if(!('username' in req.body.user.properties)) return res.status(400).send(`Username missing`)

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
      SET user = $user.properties

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

}

exports.delete_user = (req, res) => {

  const user_id = req.params.user_id
    ?? req.query.user_id
    ?? req.query.id
    // DO NOT PUT CURRENT USER HERE

  if(user_id === 'self') user_id = get_current_user_id(res)


  const session = driver.session()
  session
  .run(`
    // Find the user
    MATCH (user:User)
    WHERE id(user) = toInteger($user_id)

    // Delete
    DETACH DELETE user

    // Return something
    RETURN 'success'
    `, {
    user_id
  })
  .then(result => {
    if(result.records.length === 0 ) return res.status(400).send(`User deletion failed`)
    res.send("User deleted successfully")
  })
  .catch(error => {
    console.error(error)
    res.status(500).send(`Error deleting user: ${error}`)
  })
  .finally(() => session.close())
}

exports.patch_user = (req, res) => {

  const user_id = self_only_unless_admin(req, res)

  let customizable_fields = [
    'avatar_src',
    'last_name',
    'display_name',
    'email_address',
    'first_name',
  ]

  if(res.locals.user.properties.isAdmin){
    customizable_fields= customizable_fields.concat([
      'isAdmin',
      'locked',
    ])
  }

  for (let [key, value] of Object.entries(req.body)) {
    if(!customizable_fields.includes(key)) {
      console.log(`Unauthorized attempt to modify property ${key}`)
      return res.status(403).send(`Unauthorized to modify ${key}`)
    }
  }


  const session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInteger($user_id)
    SET user += $properties // += implies update of existing properties
    RETURN user
    `, {
    user_id,
    properties: req.body,
  })
  .then(result => {
    res.send(result.records)
  })
  .catch(error => { res.status(500).send(`Error updating property: ${error}`) })
  .finally(() => session.close())



}

exports.update_password = (req, res) => {

  // Input sanitation
  const new_password = req.body.new_password
    || req.body.password

  if(!new_password) return res.status(400).send(`Password missing from body`)

  const user_id = self_only_unless_admin(req, res)

  // Hash the provided password
  bcrypt.hash(new_password, 10, (err, new_password_hashed) => {
    if(err) return res.status(500).send(`Error hashing password: ${err}`)

    const session = driver.session();
    session
    .run(`
      // Find the user using ID
      MATCH (user:User)
      WHERE id(user) = toInteger($user_id)

      // Set the new password
      SET user.password_hashed = $new_password_hashed

      // Return user once done
      RETURN user
      `, {
        user_id,
        new_password_hashed,
      })
      .then(result => { res.send(result.records) })
      .catch(error => res.status(400).send(`Error accessing DB: ${error}`))
      .finally( () => session.close())
  })
}

exports.get_all_users = (req, res) => {
  // Protecting this route might be necessary
  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    RETURN user
    LIMIT 100
    `, {})
  .then(result => {
    res.send(result.records)
  })
  .catch(error => { res.status(500).send(`Error getting users: ${error}`) })
  .finally(() => session.close())
}

exports.create_admin_if_not_exists = () => {

  const default_admin_password = process.env.DEFAULT_ADMIN_PASSWORD || 'administrator'

  bcrypt.hash(default_admin_password, 10, (err, hash) => {
    if(err) console.log(`Error hashing password: ${err}`)

    const session = driver.session();
    session
    .run(`
      // Create a dummy node so that the administrator account does not get ID 0
      MERGE (dummy:DummyNode)

      // Find the administrator account or create it if it does not exist
      MERGE (administrator:User {username:"administrator"})

      // Make the administrator an actual administrator
      SET administrator.isAdmin = true

      // Check if the administrator account is missing its password
      // If the administrator account does not have a password (newly created), set it
      WITH administrator
      WHERE NOT EXISTS(administrator.password_hashed)
      SET administrator.password_hashed = $default_admin_password_hashed
      SET administrator.display_name = 'Administrator'

      // Return the account
      RETURN 'OK'
      `, {
        default_admin_password_hashed: hash
      })
      .then(result => {
        if(result.records.length > 0) {
          console.log(`Administrator account created`)
        }
        else {
          console.log(`Administrator already existed`)
        }

      })
      .catch(error => { console.log(error)})
      .finally( () => session.close())
  })
}
