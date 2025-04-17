require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GitLabStrategy = require('passport-gitlab2').Strategy;
const BitbucketStrategy = require('passport-bitbucket-oauth2').Strategy;
const path = require('path');
const cors = require('cors');

const app = express();

app.use(cors({
  origin: 'http://localhost:3000', // your frontend URL
  credentials: true, // allow cookies
}));

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

passport.use('gitlab', new GitLabStrategy({
  clientID: process.env.GITLAB_CLIENT_ID,
  clientSecret: process.env.GITLAB_CLIENT_SECRET,
  callbackURL: process.env.GITLAB_CALLBACK_URL,
},
(gitlabAccessToken, refreshToken, profile, done) => {
  const user = {
    provider: 'gitlab',
    id: profile.id,
    username: profile.username,
    displayName: profile.displayName || profile.username,
    email: profile.emails?.[0]?.value,
    profileUrl: profile.profileUrl,
    accessToken: gitlabAccessToken
  };
  return done(null, user);
}));

passport.use('bitbucket', new BitbucketStrategy({
  clientID: process.env.BITBUCKET_CLIENT_ID,
  clientSecret: process.env.BITBUCKET_CLIENT_SECRET,
  callbackURL: process.env.BITBUCKET_CALLBACK_URL,
},
(bitbucketAccessToken, refreshToken, profile, done) => {
  const user = {
    provider: 'bitbucket',
    id: profile.id,
    username: profile.username,
    displayName: profile.displayName || profile.username,
    email: profile.email || (profile.emails && profile.emails[0] && profile.emails[0].value),
    profileUrl: `https://bitbucket.org/${profile.username}/`,
    accessToken: bitbucketAccessToken
  };
  return done(null, user);
}));

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
app.get('/oauth/gitlab/callback',
  passport.authenticate('gitlab', { failureRedirect: '/' }),
  (req, res) => res.redirect('/profile')
);

app.get('/auth/bitbucket', passport.authenticate('bitbucket'));
app.get('/oauth/bitbucket/callback',
  passport.authenticate('bitbucket', { failureRedirect: '/' }),
  (req, res) => res.redirect('/profile')
);

app.get('/profile', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'profile.html'));
});

app.get('/user-data', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Not authenticated' });
  
  const user = req.user;
  res.json({
    provider: user.provider,
    id: user.id,
    displayName: user.displayName,
    username: user.username,
    email: user.email,
    profileUrl: user.profileUrl
  });
});

app.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).send('Failed to logout');
    res.redirect('/');
  });
});

app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`GitLab callback: ${process.env.GITLAB_CALLBACK_URL}`);
  console.log(`Bitbucket callback: ${process.env.BITBUCKET_CALLBACK_URL}`);
});