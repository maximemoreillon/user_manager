const driver = require('../neo4j_driver.js')
const bcrypt = require('bcrypt')


function self_only_unless_admin_v2(req, res){

  // Todo: error message if user is not admin and tries to edit another user

  let current_user_is_admin = !!res.locals.user.properties.isAdmin

  if(current_user_is_admin) {
    return req.body.user_id
      || req.query.user_id
      || req.params.user_id
      || res.locals.user.identity.low
  }
  else {
    return res.locals.user.identity.low
  }

}

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


exports.get_user = (req, res) => {

  let user_id = req.params.user_id
    || req.query.user_id
    || req.query.id
    || res.locals.user.identity.low


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
}

exports.create_user = (req, res) => {

  // Todo: Check if username is already used

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

}

exports.delete_user = (req, res) => {

  let user_id = req.params.user_id
    || req.query.user_id
    || req.query.id

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
    user_id: user_id
  })
  .then(result => {
    if(result.records.length === 0 ) return res.status(400).send(`User deletion failed`)
    res.send("User deleted successfully")
  })
  .catch(error => { res.status(500).send(`Error deleting user: ${error}`) })
  .finally(() => session.close())
}

exports.patch_user = (req, res) => {

  let customizable_fields = [
    'avatar_src',
    'last_name',
    'display_name',
    'email_address',
    'first_name',
  ]

  if(res.locals.user.properties.isAdmin){
    customizable_fields.push('isAdmin')
  }

  for (let [key, value] of Object.entries(req.body)) {
    if(!customizable_fields.includes(key)) {
      delete req.body[key]
    }
  }


  var session = driver.session()
  session
  .run(`
    MATCH (user:User)
    WHERE id(user) = toInt({user_id})
    SET user += {properties} // += implies update of existing properties
    RETURN user
    `, {
    user_id: self_only_unless_admin_v2(req, res),
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
}

exports.get_all_users = (req, res) => {
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
}
