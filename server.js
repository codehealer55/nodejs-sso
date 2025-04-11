require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GitLabStrategy = require('passport-gitlab2').Strategy;
const path = require('path');

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  cookie: { 
    secure: false, // Set to true if using HTTPS
    maxAge: 24 * 60 * 60 * 1000 // 24 hours
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Passport GitLab Strategy
passport.use(new GitLabStrategy({
  clientID: process.env.GITLAB_CLIENT_ID,
  clientSecret: process.env.GITLAB_CLIENT_SECRET,
  callbackURL: process.env.GITLAB_CALLBACK_URL,
},
(accessToken, refreshToken, profile, done) => {
  // Simple user transformation
  const user = {
    id: profile.id,
    username: profile.username,
    displayName: profile.displayName || profile.username,
    email: profile.emails?.[0]?.value,
    profileUrl: profile.profileUrl,
    provider: profile.provider,
    accessToken: accessToken
  };
  return done(null, user);
}));

// Passport serialization
passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((obj, done) => {
  done(null, obj);
});

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/auth/gitlab', passport.authenticate('gitlab'));

app.get('/oauth/callback',
  passport.authenticate('gitlab', { 
    failureRedirect: '/',
    failureFlash: true 
  }),
  (req, res) => {
    res.redirect('/profile');
  }
);

app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect('/');
  }
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/user-data', (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  
  const user = req.user;
  res.json({
    id: user.id,
    displayName: user.displayName,
    username: user.username,
    email: user.emails?.[0]?.value,
    profileUrl: user.profileUrl,
    provider: user.provider
  });
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).send('Failed to logout');
    }
    res.redirect('/');
  });
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Something broke!');
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`GitLab OAuth configured with callback: ${process.env.GITLAB_CALLBACK_URL}`);
});