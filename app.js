var createError = require('http-errors');
var express = require("express"),
    bodyParser = require("body-parser"),
    swaggerJsdoc = require("swagger-jsdoc"),
    swaggerUi = require("swagger-ui-express");
const { Sequelize, DATE } = require('sequelize');
const { sequelize, Role } = require('./models');

var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

const authRouter = require('./routes/auth');
const rolesRouter = require('./routes/roles');
const usersRouter = require('./routes/users');
var pjson = require('./package.json');

var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
global.__domainUri = "http://localhost:3000";

app.use('/api', authRouter);
app.use('/api', rolesRouter);
app.use('/api', usersRouter);
try {
  sequelize.authenticate();
  console.log('Connection has been established successfully.');
} catch (error) {
  console.error('Unable to connect to the database:', error);
}

const options = {
  definition: {
      openapi: "3.0.0",
      info: {
          title: "Express API with Swagger",
          version: pjson.version,
          description: "This is a simple CRUD API application made with Express and documented with Swagger",
      },
      servers: [{
          url: "http://localhost:3000/api",
      }],
  },
  apis: ["./routes/*.js"],
};

const specs = swaggerJsdoc(options);
app.use(
  "/",
  swaggerUi.serve,
  swaggerUi.setup(specs)
);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;
