require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');

const app = express();

const saltRounds = 12;
const PORT = process.env.PORT || 3000;
// expire time set at 1 hour calculated in milliseconds
const expireTime = 60 * 60 * 1000;

// secret information section
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const session_secret = process.env.NODE_SESSION_SECRET;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const mongoUrl = `mongodb+srv://${mongodb_user}:${mongodb_password}` +
                 `@${mongodb_host}/${mongodb_database}` +
                 `?retryWrites=true&w=majority`;

const client = new MongoClient(mongoUrl);

let userCollection;

app.use(express.urlencoded({ extended: false }));
app.use(express.static(__dirname + '/public'));

var mongoStore = MongoStore.create(
{
    mongoUrl: mongoUrl,
    crypto:
    {
        secret: mongodb_session_secret
    }
});

app.use(session(
{
    secret: session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.get('/', (req, res) =>
{
    if (req.session.authenticated)
    {
        var html = `
            <h1>Hello, ${req.session.name}</h1>
            <a href='/members'>Members Place</a>
            <a href='/logout'>Logout</a>
        `;
        res.send(html);
    }
    else
    {
        var html = `
            <h1>Home</h1>
            <a href='/signup'>Sign Up</a>
            <a href='/login'>Log In</a>
        `;
        res.send(html);
    }
});

app.get('/signup', (req, res) =>
{
    var html = `
        <h1>Sign Up</h1>
        <form action='/signupSubmit' method='post'>
            <input name='name' type='text' placeholder='Name'>
            <input name='email' type='text' placeholder='Email'>
            <input name='password' type='password' placeholder='Password'>
            <button>Submit</button>
        </form>
    `;
    res.send(html);
});

app.post('/signupSubmit', async (req, res) =>
{
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
    {
        name: Joi.string().max(50).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const validationResult = schema.validate({ name, email, password });

    if (validationResult.error != null)
    {
        var html = `
            ${validationResult.error.details[0].message}
            <a href='/signup'>Try again</a>
        `;
        res.send(html);
        return;
    }

    const existingUser = await userCollection.findOne({ email: email });

    if (existingUser)
    {
        var html = `
            Email already exists.
            <a href='/signup'>Try again</a>
        `;
        res.send(html);
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ name: name, email: email, password: hashedPassword });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.cookie.maxAge = expireTime;

    req.session.save(() =>
    {
        res.redirect('/members');
    });
});

app.get('/login', (req, res) =>
{
    var html = `
        <h1>Log In</h1>
        <form action='/loginSubmit' method='post'>
            <input name='email' type='text' placeholder='Email'>
            <input name='password' type='password' placeholder='Password'>
            <button>Submit</button>
        </form>
    `;
    res.send(html);
});

app.post('/loginSubmit', async (req, res) =>
{
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
    {
        email: Joi.string().email().required(),
        password: Joi.string().max(50).required()
    });

    const validationResult = schema.validate({ email, password });

    if (validationResult.error != null)
    {
        var html = `
            ${validationResult.error.details[0].message}
            <a href='/login'>Try again</a>
        `;
        res.send(html);
        return;
    }

    const user = await userCollection.findOne({ email: email });

    if (!user)
    {
        var html = `
            User not found.
            <a href='/login'>Try again</a>
        `;
        res.send(html);
        return;
    }

    if (await bcrypt.compare(password, user.password))
    {
        req.session.authenticated = true;
        req.session.name = user.name;
        req.session.cookie.maxAge = expireTime;

        req.session.save(() =>
        {
            res.redirect('/members');
        });
        return;
    }
    else
    {
        var html = `
            Invalid password.
            <a href='/login'>Try again</a>
        `;
        res.send(html);
        return;
    }
});

app.get('/members', (req, res) =>
{
    if (!req.session.authenticated)
    {
        res.redirect('/');
        return;
    }

    const images =
    [
        '/Darth_umanaga.png',
        '/sebastionhohoho.png',
        '/the_filalfel_castro.png'
    ];

    var randomNumber = Math.floor(Math.random() * images.length);

    var html = `
        <h1>Hello, ${req.session.name}</h1>
        <img src='${images[randomNumber]}' width='300'>
        <a href='/'>Home</a>
        <a href='/logout'>Logout</a>
    `;
    res.send(html);
});

app.get('/logout', (req, res) =>
{
    req.session.destroy(() =>
    {
        res.redirect('/');
    });
});

app.use((req, res) =>
{
    res.status(404);
    res.send('Page not found - 404');
});

async function connectDatabase()
{
    await client.connect();
    const db = client.db(mongodb_database);
    userCollection = db.collection('users');
}

connectDatabase().then(() =>
{
    app.listen(PORT, () =>
    {
        console.log(`Server is running on port ${PORT}`);
    });
});