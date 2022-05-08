const User = require("./models/User");
const jwt =require("jsonwebtoken")
const findOrCreate = require('mongoose-findorcreate')

const GoogleStrategy = require("passport-google-oauth20").Strategy;
// const GithubStrategy = require("passport-github2").Strategy;
// const FacebookStrategy = require("passport-facebook").Strategy;

const passport = require("passport");

// MONGO_URL = mongodb + srv://AkashMDB:atktmdb123%40@cluster0.wt1qr.mongodb.net/myFirstDatabase?retryWrites=true&w=majority
// GOOGLE_CLIENT_ID = 762736905727 - u4gko4aeh379p4g9qt4rh067e2hhdclc.apps.googleusercontent.com
// GOOGLE_CLIENT_SECRET = GOCSPX - PTisS3DQJYXAa0OM8aktBwR9hHbx



const GOOGLE_CLIENT_ID = "762736905727-u4gko4aeh379p4g9qt4rh067e2hhdclc.apps.googleusercontent.com"
    ;
const GOOGLE_CLIENT_SECRET = "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";

;


const defaultScope = [
    'https://www.googleapis.com/auth/plus.me',
    'https://www.googleapis.com/auth/userinfo.email',
];


passport.use(
    new GoogleStrategy(
        {
            clientID: GOOGLE_CLIENT_ID,
            clientSecret: GOOGLE_CLIENT_SECRET,
            callbackURL: "/api/auth/google/callback",
            scope: defaultScope
        },
        function (accessToken, refreshToken, profile, done) {
            done(null, profile);
        }
    )
);

// passport.use(
//     new GithubStrategy(
//         {
//             clientID: GITHUB_CLIENT_ID,
//             clientSecret: GITHUB_CLIENT_SECRET,
//             callbackURL: "/auth/github/callback",
//         },
//         function (accessToken, refreshToken, profile, done) {
//             done(null, profile);
//         }
//     )
// );

// passport.use(
//     new FacebookStrategy(
//         {
//             clientID: FACEBOOK_APP_ID,
//             clientSecret: FACEBOOK_APP_SECRET,
//             callbackURL: "/auth/facebook/callback",
//         },
//         function (accessToken, refreshToken, profile, done) {
//             done(null, profile);
//         }
//     )
// );

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});
