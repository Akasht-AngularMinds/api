const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt=require("jsonwebtoken");
const passport = require("passport")

const generateAccessToken = (user) => {
    return jwt.sign({ id: user.id }, "mySecretKey", {
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
    if(!user){return 
      res.status(404).json("user not found");
    }
    console.log(user)
    const validPassword = await bcrypt.compare(req.body.password, user.password)
    if(!validPassword){
      return res.status(400).json("wrong password")
    }
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

router.get("/login/success",async (req, res) => {
  let em = req.user ? req.user._json.email:""
  let localUser = await User.findOne({ email:em})
  console.log(localUser)
  if (localUser){

    let accessToken = jwt.sign({ id: localUser._id }, "mySecretKey", {
      expiresIn: "9000s",
    });
  if (req.user) {
    res.status(200).json({
      success: true,
      message: "successfull",
      user: { localUser, accessToken}
      //   cookies: req.cookies
    });
  }
  }else{
    res.status("404").json("please signup")
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

router.get("/google", passport.authenticate("google", { scope: ["profile"] }));

router.get(
  "/google/callback",
  passport.authenticate("google", {
    successRedirect: CLIENT_URL,
    failureRedirect: "/login/failed",
  })
);


router.post("/google_Login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    console.log(user);
    if (user) {
      const accessToken = generateAccessToken(user);
      res.status(200).json({
        user: user,
        accessToken,
        message: "login  successfully",
      });
      
    } else {
      res.json({ status: false, error: "user not found" });
    }
  } catch (err) {
    console.log(err);
    res.status(500).json(err);
  }
});


module.exports = router