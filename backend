const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const { v4: uuid } = require("uuid");
const fs = require("fs-extra");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));

// ---------------------------
// Storage Setup (JSON files)
// ---------------------------
const DB = {
    users: "./users.json",
    snippets: "./snippets.json",
};

// Ensure files exist
if (!fs.existsSync(DB.users)) fs.writeJsonSync(DB.users, []);
if (!fs.existsSync(DB.snippets)) fs.writeJsonSync(DB.snippets, []);

// ---------------------------
// Sessions
// ---------------------------
app.use(
    session({
        secret: "supersecretkey",          // change to env variable
        resave: false,
        saveUninitialized: false,
        cookie: { maxAge: 1000 * 60 * 60 },
    })
);

// Helper: Require Login
function requireLogin(req, res, next) {
    if (!req.session?.user) {
        return res.status(401).json({ error: "Not logged in" });
    }
    next();
}

// ---------------------------
// AUTH: Register
// ---------------------------
app.post("/register", async (req, res) => {
    let { username, password } = req.body;

    if (!username || !password)
        return res.status(400).json({ error: "Missing fields." });

    username = username.trim().toLowerCase();

    const users = await fs.readJson(DB.users);

    if (users.find((u) => u.username === username))
        return res.status(400).json({ error: "Username exists." });

    const hash = await bcrypt.hash(password, 10);

    users.push({
        id: uuid(),
        username,
        password: hash,
    });

    await fs.writeJson(DB.users, users, { spaces: 2 });

    res.json({ success: true });
});

// ---------------------------
// AUTH: Login
// ---------------------------
app.post("/login", async (req, res) => {
    const { username, password } = req.body;

    const users = await fs.readJson(DB.users);
    const user = users.find((u) => u.username === username.toLowerCase());

    if (!user) return res.status(400).json({ error: "Invalid login." });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ error: "Invalid login." });

    req.session.user = { id: user.id, username: user.username };
    res.json({ success: true });
});

// ---------------------------
// AUTH: Logout
// ---------------------------
app.post("/logout", (req, res) => {
    req.session.destroy(() => {
        res.json({ success: true });
    });
});

// ---------------------------
// SNIPPETS: Create
// ---------------------------
app.post("/snippets", requireLogin, async (req, res) => {
    const { title, language, description, code, tags = [] } = req.body;

    // Validation
    if (!title || title.length < 1 || title.length > 100)
        return res.status(400).json({ error: "Invalid title" });

    if (!code || code.length < 1)
        return res.status(400).json({ error: "Code required" });

    if (!Array.isArray(tags) || tags.length > 5)
        return res.status(400).json({ error: "Tag error" });

    const cleanedTags = [...new Set(tags.map((t) => t.trim().toLowerCase()))];

    const snippets = await fs.readJson(DB.snippets);

    const newSnippet = {
        id: uuid(),
        owner: req.session.user.id,
        title,
        language,
        description: description || "",
        code,
        tags: cleanedTags,
        created: Date.now(),
    };

    snippets.push(newSnippet);
    await fs.writeJson(DB.snippets, snippets, { spaces: 2 });

    res.json(newSnippet);
});

// ---------------------------
// SNIPPETS: Get My Snippets
// ---------------------------
app.get("/snippets", requireLogin, async (req, res) => {
    const snippets = await fs.readJson(DB.snippets);
    const mine = snippets
        .filter((s) => s.owner === req.session.user.id)
        .sort((a, b) => b.created - a.created);

    res.json(mine);
});

// ---------------------------
// SNIPPETS: Search & Filter
// ---------------------------
app.get("/snippets/search", requireLogin, async (req, res) => {
    const { q = "", language, tags } = req.query;

    const search = q.toLowerCase();
    const tagList = tags ? tags.split(",").map((t) => t.trim().toLowerCase()) : [];

    const snippets = await fs.readJson(DB.snippets);

    let mine = snippets.filter((s) => s.owner === req.session.user.id);

    // Basic search: title OR description OR code (case-insensitive)
    if (search) {
        mine = mine.filter(
            (s) =>
                s.title.toLowerCase().includes(search) ||
                s.description.toLowerCase().includes(search) ||
                s.code.toLowerCase().includes(search)
        );
    }

    // Language filter
    if (language && language !== "all") {
        mine = mine.filter((s) => s.language.toLowerCase() === language.toLowerCase());
    }

    // Tags (AND logic)
    if (tagList.length > 0) {
        mine = mine.filter((s) =>
            tagList.every((tag) => s.tags.includes(tag))
        );
    }

    res.json(mine);
});

// ---------------------------
// SNIPPETS: Edit
// ---------------------------
app.put("/snippets/:id", requireLogin, async (req, res) => {
    const { id } = req.params;
    const { title, language, description, code, tags = [] } = req.body;

    const snippets = await fs.readJson(DB.snippets);
    const snip = snippets.find((s) => s.id === id);

    if (!snip) return res.status(404).json({ error: "Not found" });
    if (snip.owner !== req.session.user.id)
        return res.status(403).json({ error: "Forbidden" });

    snip.title = title || snip.title;
    snip.language = language || snip.language;
    snip.description = description || snip.description;
    snip.code = code || snip.code;

    if (Array.isArray(tags))
        snip.tags = [...new Set(tags.map((t) => t.trim().toLowerCase()))];

    await fs.writeJson(DB.snippets, snippets, { spaces: 2 });

    res.json(snip);
});

// ---------------------------
// SNIPPETS: Delete
// ---------------------------
app.delete("/snippets/:id", requireLogin, async (req, res) => {
    const { id } = req.params;

    const snippets = await fs.readJson(DB.snippets);
    const index = snippets.findIndex((s) => s.id === id);

    if (index === -1) return res.status(404).json({ error: "Not found" });
    if (snippets[index].owner !== req.session.user.id)
        return res.status(403).json({ error: "Forbidden" });

    snippets.splice(index, 1);
    await fs.writeJson(DB.snippets, snippets, { spaces: 2 });

    res.json({ success: true });
});

// ---------------------------
// SERVER START
// ---------------------------
const PORT = 3000;
app.listen(PORT, () =>
    console.log(`✔ Code Snippet Manager backend running on port ${PORT}`)
);
