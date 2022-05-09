const User = require("../models/User");
const router = require("express").Router();
const bcrypt = require("bcrypt");
const jwt =require("jsonwebtoken")
const upload = require("../middleware/upload");
const mongoose = require("mongoose");


var validatePassword = function(pass) {
  var re = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/  ;
  return re.test(pass)
};

const verify = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, "mySecretKey", (err, user) => {
      if (err) {
        return res.status(403).json("Token is not valid!");
      }
      console.log(user)
      req.user = user;
      next();
    });
  } else {
  return  res.status(401).json("You are not authenticated!");
  }
};


router.put("/password/:id",verify, async(req,res)=>{
  mongoose.set('useFindAndModify', false);
  try {
  
  if (req.user.id == req.params.id) {
    
    if (req.body.password && req.body.newPassword)  {
        
      let checkValidation= validatePassword(req.body.newPassword)
      if(!checkValidation){
         return res.status(403).json({ 
           error:"new password should contain digit,special Character,alphabate and length should be greater than 6 "
         })
      }
      const oldData = await User.findById({_id:req.body.userId});
     
  
      const validPassword = await bcrypt.compare(req.body.password, oldData.password)
      console.log(validPassword)
      if (!validPassword) {
        return res.status(404).json({error: "old password does not match"});
      }

      const salt = await bcrypt.genSalt(12);
      req.body.password= await bcrypt.hash(req.body.newPassword, salt);
        

        //  console.log(np)
        const user = await User.findByIdAndUpdate(req.params.id, {
          $set: req.body
        });
  
        const user1 = await User.findById(req.params.id);
        return res.status(200).json(
          {
            message:"suceess",
            user:user1
          }
        );

     
    }else{
      return res.status(403).json("password or newPassword cannot be empty!");

    }
  } else {
    return res.status(403).json("You can update only your account!");
  }
} catch (err) {
console.log(err)
  return res.status(500).json(err);
}
})

//update user
router.put("/:id", verify, upload.single("image"), async (req, res) => {
  mongoose.set('useFindAndModify', false);
  if (req.user.id === req.params.id || req.body.isAdmin) {
      
    try {
      const oldUserData = await User.findById(req.params.id);
     
      if(req.body.removeProfile=="true"){
        
        const user = await User.findByIdAndUpdate(req.params.id, {
          $set: req.body, profilePicture: ""
        });
        const user1 = await User.findById(req.params.id);

       return res.status(200).json({ user1, message: "profile picture removed successfully" });

      }

      const user = await User.findByIdAndUpdate(req.params.id, {    
        $set: req.body, profilePicture: req.file ? req.file.path : oldUserData.profilePicture
      });
      const user1 = await User.findById(req.params.id);
      return res.status(200).json({user1,message:"Account has been updated"});
    } catch (err) {
      return res.status(500).json(err);
    }
  } else {
    return res.status(403).json("You can update only your account!");
  }
});

//delete user
router.delete("/:id", async (req, res) => {
  if (req.body.userId === req.params.id || req.body.isAdmin) {
    try {
      await User.findByIdAndDelete(req.params.id);
      res.status(200).json("Account has been deleted");
    } catch (err) {
      return res.status(500).json(err);
    }
  } else {
    return res.status(403).json("You can delete only your account!");
  }
});

//get a user
router.get("/", async (req, res) => {
  const userId = req.query.userId;
  const username = req.query.username;
  try {
    const user = userId
      ? await User.findById(userId)
      : await User.findOne({ username: username });
    const { password, updatedAt, ...other } = user._doc;
  return  res.status(200).json(other);
  } catch (err) {
  return  res.status(500).json(err);
  }
});









module.exports = router;
