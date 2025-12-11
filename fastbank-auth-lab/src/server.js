const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const app = express();
const PORT = 3001;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static("public"));


const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 12) // FIXED: bcrypt instead of fastHash
  }
];

const sessions = {};

function generateSessionToken() {
  return crypto.randomBytes(32).toString("hex"); // FIXED: unpredictable token
}


function authenticate(req, res, next) {
  const token = req.cookies.session;
  if (!token || !sessions[token]) {
    return res.status(401).json({ authenticated: false });
  }

  const session = sessions[token];

  
  if (Date.now() > session.expires) {
    delete sessions[token];
    res.clearCookie("session");
    return res.status(401).json({ authenticated: false });
  }

  req.userId = session.userId;
  next();
}


app.get("/api/me", authenticate, (req, res) => {
  const user = users.find((u) => u.id === req.userId);
  res.json({ authenticated: true, username: user.username });
});


app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);


  if (!user) {
    await bcrypt.hash(password, 10);
    return res
      .status(401)
      .json({ success: false, message: "Invalid username or password" });
  }

  
  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res
      .status(401)
      .json({ success: false, message: "Invalid username or password" });
  }

  const token = generateSessionToken();

  
  sessions[token] = {
    userId: user.id,
    expires: Date.now() + 30 * 60 * 1000
  };


  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 30 * 60 * 1000
  });

  res.json({ success: true });
});


app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token && sessions[token]) delete sessions[token];
  res.clearCookie("session");
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`FastBank Auth Lab running securely at https://localhost:${PORT}`);
});
