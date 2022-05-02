const User  = require("../models/User");
const router = require("express").Router();
const bcrypt = require("bcrypt");
const path = require("path");
const multer = require("multer");


const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, "public/images");
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + file.originalname);
    },
});

const upload = multer({ storage: storage });

    // console.log(upload)   
    router.post("/", upload.single("image"), (req, res) => {
        try {
            console.log(req.file)
            res.status(200).json({file:req.file,message:"File uploded successfully"});
        } catch (error) {
            console.error(error);
        }
    });
// const verify = (req, res, next) => {
//   const authHeader = req.headers.authorization;
//   if (authHeader) {
//     const token = authHeader.split(" ")[1];

//     jwt.verify(token, "mySecretKey", (err, user) => {
//       if (err) {
//         return res.status(403).json("Token is not valid!");
//       }
//       console.log(user)
//       req.user = user;
//       next();
//     });
//   } else {
//     res.status(401).json("You are not authenticated!");
//   }
// };
  router.post("/up",(req,res)=>{
      res.send("post req")
  })


module.exports = router;
