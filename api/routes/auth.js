const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt=require("jsonwebtoken");
const passport = require("passport")

const generateAccessToken = (user) => {
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
      expiresIn: "9000s",
    });
  };
  var validatePassword = function(pass) {
    var re = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/  ;
    return re.test(pass)
  };

//REGISTER
router.post("/register", async (req, res) => {
  try {
    console.log("hello")
    const userv = await User.findOne({ email: req.body.email });
    console.log(userv)
    if(userv){
      return  res.status(500).json("user already exist");
    }

    let passval=validatePassword(req.body.password)
    console.log(passval)
    console.log(passval)
    //generate new password
    if(passval ){
    const salt = await bcrypt.genSalt(10);
    var hashedPassword = await bcrypt.hash(req.body.password, salt);
    

    }else{
      return  res.status(404).json("password is not valid");

    }


    //create new user
    const newUser = new User({
      firstname: req.body.firstname,
      lastname:req.body.lastname,
      email: req.body.email,
      password: hashedPassword,
      isAdmin:req.body.isAdmin,
    
    });

    //save user and respond
    const user = await newUser.save();
    res.status(200).json(user);
  } catch (err) {
    res.status(500).json(err)
  }
});

//LOGIN
router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    !user && res.status(404).json("user not found");
    console.log(user)
    const validPassword = await bcrypt.compare(req.body.password, user.password)
    !validPassword && res.status(400).json("wrong password")
     console.log(validPassword)
    const accessToken = generateAccessToken(user);
    console.log(user)
    res.json({
      // firstname: user.firstname,
      // lastname:user.lastname,
      // isAdmin: user.isAdmin,
       accessToken,
      // userId: user._id
      user
    });

  } catch (err) {
    res.status(500).json(err)
  }
});
//-------------------------------------------other logins----------------------------------------------------
const CLIENT_URL = "http://localhost:3000/";

router.get("/login/success", (req, res) => {
  if (req.user) {
    res.status(200).json({
      success: true,
      message: "successfull",
      user: req.user,
      //   cookies: req.cookies
    });
  }
});

router.get("/login/failed", (req, res) => {
  res.status(401).json({
    success: false,
    message: "failure",
  });
});

router.get("/logout", (req, res) => {
  req.logout();
  res.redirect(CLIENT_URL);
});

router.get("/google", passport.authenticate("google", { scope: ["https://www.googleapis.com/auth/userinfo.profile"] }));

router.get(
  "/google/callback",
  passport.authenticate("google", {
    successRedirect: CLIENT_URL,
    failureRedirect: "/login/failed",
  })
);

router.get("/github", passport.authenticate("github", { scope: ["profile"] }));

router.get(
  "/github/callback",
  passport.authenticate("github", {
    successRedirect: CLIENT_URL,
    failureRedirect: "/login/failed",
  })
);

router.get("/facebook", passport.authenticate("facebook", { scope: ["profile"] }));

router.get(
  "/facebook/callback",
  passport.authenticate("facebook", {
    successRedirect: CLIENT_URL,
    failureRedirect: "/login/failed",
  })
);

module.exports = router;
