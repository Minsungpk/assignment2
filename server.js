require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const Joi = require("joi");

const app = express();
const PORT = process.env.PORT || 8000;

// MongoDB setup
const client = new MongoClient(process.env.MONGODB_URI);
let db;

async function connectDB() {
    await client.connect();
    db = client.db("usersDB");
    console.log("Connected to MongoDB");
}
connectDB();

// Joi validation schemas
const signupSchema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().max(100).required(),
    password: Joi.string().max(100).required()
});

const loginSchema = Joi.object({
    email: Joi.string().email().max(100).required(),
    password: Joi.string().max(100).required()
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI
    }),
    cookie: {
        maxAge: 1000 * 60 * 60 // 1 hour
    }
}));

// -------------------- HOME --------------------
app.get("/", (req, res) => {
    res.send(`
        <h1>Home Page</h1>

        <img src="/image1.jpg" width="300">
        <img src="/image2.jpg" width="300">
        <img src="/image3.jpg" width="300">

        <br><br>
        <a href="/signup">Go to Signup</a><br>
        <a href="/login">Go to Login</a><br>
        <a href="/members">Go to Members</a>
    `);
});

// -------------------- SIGNUP --------------------
app.get("/signup", (req, res) => {
    res.send(`
        <h1>Signup Page</h1>

        <form method="POST" action="/signup">
            <input name="name" placeholder="Name" required><br>
            <input name="email" placeholder="Email" required><br>
            <input name="password" type="password" placeholder="Password" required><br>
            <button type="submit">Sign Up</button>
        </form>

        <br>
        <a href="/">Go home</a>
    `);
});

app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;

    const validationResult = signupSchema.validate({ name, email, password });

    if (validationResult.error) {
        return res.send(`
            <h1>Signup failed</h1>
            <p>Invalid input.</p>
            <a href="/signup">Try again</a>
        `);
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await db.collection("users").insertOne({
        name,
        email,
        password: hashedPassword
    });

    res.send(`
        <h1>User created</h1>
        <p>Name: ${name}</p>
        <p>Email: ${email}</p>
        <a href="/login">Go to login</a>
    `);
});

// -------------------- LOGIN --------------------
app.get("/login", (req, res) => {
    res.send(`
        <h1>Login Page</h1>

        <form method="POST" action="/login">
            <input name="email" placeholder="Email" required><br>
            <input name="password" type="password" placeholder="Password" required><br>
            <button type="submit">Log In</button>
        </form>

        <br>
        <a href="/">Go home</a>
    `);
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const validationResult = loginSchema.validate({ email, password });

    if (validationResult.error) {
        return res.send(`
            <h1>Login failed</h1>
            <p>Invalid input.</p>
            <a href="/login">Try again</a>
        `);
    }

    const user = await db.collection("users").findOne({ email });

    if (!user) {
        return res.send(`
            <h1>Login failed</h1>
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `);
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
        return res.send(`
            <h1>Login failed</h1>
            <p>Invalid email/password combination.</p>
            <a href="/login">Try again</a>
        `);
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;

    res.redirect("/members");
});

// -------------------- MEMBERS --------------------
app.get("/members", (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/");
    }

    const images = ["image1.jpg", "image2.jpg", "image3.jpg"];
    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1>Members Page</h1>
        <p>Hello, ${req.session.name}</p>

        <img src="/${randomImage}" width="300">

        <br><br>
        <a href="/logout">Log out</a>
    `);
});

// -------------------- LOGOUT --------------------
app.get("/logout", (req, res) => {
    req.session.destroy();
    res.redirect("/");
});

// -------------------- 404 --------------------
app.use((req, res) => {
    res.status(404).send(`
        <h1>404</h1>
        <p>Page not found</p>
        <a href="/">Go home</a>
    `);
});

// -------------------- SERVER --------------------
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});