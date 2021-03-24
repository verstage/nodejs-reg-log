const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const mongoose = require('mongoose');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');

const app = express();

//Passport Config
require('./config/passport')(passport);

//Connect to database
const db = require('./config/keys').MongoURI;


mongoose.connect(db, { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => {console.log('MongoDB connected...')})
    .catch(err => console.log(err));

//Ejs
app.use(expressLayouts);
app.set('view engine', 'ejs');

//Bodyparser for forms
app.use(express.urlencoded({extended: false}));

//Express Session
app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true,
}));

//Passport middleware
app.use(passport.initialize());
app.use(passport.session());

//Connect flash
app.use(flash());

//Global vars
app.use((req, res, next) => {
    res.locals.success_msg = req.flash('success_msg');
    res.locals.error_msg = req.flash('error_msg');
    res.locals.error = req.flash('error');
    next();
});


//Routes
app.use('/', require('./routes/index'));
app.use('/users', require('./routes/users'));


const PORT = process.env.PORT || 5000;
app.listen(PORT, console.log(`Server is running on port: ${PORT}`));
