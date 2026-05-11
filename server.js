require("dotenv").config();

const express = require("express");
const bcrypt = require("bcrypt");
const { MongoClient } = require("mongodb");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const Joi = require("joi");

const app = express();
app.set("view engine", "ejs");

const PORT = process.env.PORT || 8000;

const client = new MongoClient(process.env.MONGODB_URI);
let db;

async function connectDB() {
    await client.connect();
    db = client.db("usersDB");
    console.log("Connected to MongoDB");
}
connectDB();

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(session({
    secret: process.env.NODE_SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
        mongoUrl: process.env.MONGODB_URI,
        collectionName: "sessions",
        ttl: 60 * 60
    }),
    cookie: {
        maxAge: 1000 * 60 * 60
    }
}));

const signupSchema = Joi.object({
    name: Joi.string().max(50).required(),
    email: Joi.string().email().max(100).required(),
    password: Joi.string().max(100).required()
});

const loginSchema = Joi.object({
    email: Joi.string().email().max(100).required(),
    password: Joi.string().max(100).required()
});

function isAdmin(req, res, next) {
    if (!req.session.authenticated) {
        return res.redirect("/login");
    }

    if (req.session.user_type !== "admin") {
        return res.status(403).render("error", {
            message: "You are not authorized to view this page."
        });
    }

    next();
}

app.get("/", (req, res) => {
    res.render("index", {
        user: req.session.name
    });
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.post("/signup", async (req, res) => {
    const { name, email, password } = req.body;

    const validationResult = signupSchema.validate({ name, email, password });

    if (validationResult.error) {
        return res.render("error", {
            message: "Signup failed. Invalid input."
        });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await db.collection("users").insertOne({
        name,
        email,
        password: hashedPassword,
        user_type: "user"
    });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.user_type = "user";

    res.redirect("/members");
});

app.get("/login", (req, res) => {
    res.render("login");
});

app.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const validationResult = loginSchema.validate({ email, password });

    if (validationResult.error) {
        return res.render("error", {
            message: "Login failed. Invalid input."
        });
    }

    const user = await db.collection("users").findOne({ email });

    if (!user) {
        return res.render("error", {
            message: "Invalid email/password combination."
        });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
        return res.render("error", {
            message: "Invalid email/password combination."
        });
    }

    req.session.authenticated = true;
    req.session.name = user.name;
    req.session.email = user.email;
    req.session.user_type = user.user_type;

    res.redirect("/members");
});

app.get("/members", (req, res) => {
    if (!req.session.authenticated) {
        return res.redirect("/");
    }

    res.render("members", {
        name: req.session.name
    });
});

app.get("/admin", isAdmin, async (req, res) => {
    const users = await db.collection("users").find().toArray();

    res.render("admin", {
        users
    });
});

app.get("/promote/:email", isAdmin, async (req, res) => {
    await db.collection("users").updateOne(
        { email: req.params.email },
        { $set: { user_type: "admin" } }
    );

    res.redirect("/admin");
});

app.get("/demote/:email", isAdmin, async (req, res) => {
    await db.collection("users").updateOne(
        { email: req.params.email },
        { $set: { user_type: "user" } }
    );

    res.redirect("/admin");
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

app.use((req, res) => {
    res.status(404).render("404");
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});