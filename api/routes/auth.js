const router = require("express").Router();
const User = require("../models/User");
const bcrypt = require("bcrypt");
const jwt=require("jsonwebtoken");

const generateAccessToken = (user) => {
    return jwt.sign({ id: user.id, isAdmin: user.isAdmin }, "mySecretKey", {
      expiresIn: "9000s",
    });
  };
  var validatePassword = function (pass) {
    var re = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/  ;
    return re.test(pass)
  };

//REGISTER
router.post("/register", async (req, res) => {
  try {
    const userv = await User.findOne({ email: req.body.email });
    if(userv){
      return  res.status(500).json("user already exist");
    }

    let passval=validatePassword(req.body.password)
    console.log(passval)
    //generate new password
    if(passval && req.body.password==req.body.cpassword){
    const salt = await bcrypt.genSalt(10);
    var hashedPassword = await bcrypt.hash(req.body.password, salt);
    var hashedCPassword = await bcrypt.hash(req.body.cpassword, salt);

    }else{
      return  res.status(404).json("password is not valid");

    }


    //create new user
    const newUser = new User({
      firstname: req.body.firstname,
      lastname:req.body.lastname,
      email: req.body.email,
      password: hashedPassword,
      cpassword:hashedCPassword
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

    const validPassword = await bcrypt.compare(req.body.password, user.password)
    !validPassword && res.status(400).json("wrong password")

    const accessToken = generateAccessToken(user);
    res.json({
      firstname: user.firstname,
      lastname:user.lastname,
      isAdmin: user.isAdmin,
      accessToken
    });

  } catch (err) {
    res.status(500).json(err)
  }
});

module.exports = router;