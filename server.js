//mongodb
require('./config/db');

const app = require('express')();
const port =  process.env.PORT ||3037;

const UserRouter = require('./api/User');

 //for accepting post form data
 const bodyParser = require('express').json;
 app.use(bodyParser());

 app.use('/user', UserRouter)

 app.listen(port, () => {
    console.log(`Server running on port ${port}`);
 })