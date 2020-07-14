// modules
const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const dotenv = require('dotenv')
const pjson = require('./package.json')

const auth = require('@moreillon/authentication_middleware')

const controller = require('./controllers/user.js')

dotenv.config()

// Port configuration
const APP_PORT = process.env.APP_PORT || 80

controller.create_admin_if_not_exists()

// Express configuration
const app = express()
app.use(bodyParser.json())
app.use(cors())
app.use(auth.authenticate)

app.get('/', (req, res) => {
  res.send({
    application_name: 'User manager API',
    author: 'Maxime MOREILLON',
    version: pjson.version,
    neo4j_url: process.env.NEO4J_URL,
    authentication_api_url: process.env.AUTHENTIATION_API_URL
  })
})

app.route('/user')
  .post(controller.create_user)
  .get(controller.get_user)
  .delete(controller.delete_user)

app.route('/users')
  .post(controller.create_user)
  .get(controller.get_all_users)

app.route('/users/:user_id')
  .get(controller.get_user)
  .delete(controller.delete_user)
  .patch(controller.patch_user)

app.route('/users/:user_id/password')
  .put(controller.update_password)

// Start server
app.listen(APP_PORT, () => {
  console.log(`User manager listening on *:${APP_PORT}`);
})
