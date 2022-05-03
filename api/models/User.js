const mongoose = require("mongoose");
const Joi = require("joi");
const passwordComplexity = require("joi-password-complexity");

var validateEmail = function (email) {
  var re = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
  return re.test(email)
};



const UserSchema = new mongoose.Schema(
  {
    firstname: {
      type: String,
      required: true,
      min: 3,
      max: 20
    },
    lastname: {
      type: String,
      required: true,
      min: 3,
      max: 20 
    },
    email : {
      type: String,     
      max: 50,    
      required:'email is required',
      validate: [validateEmail, 'Please fill a valid email address'],
      match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    password: {
      type: String,   
      required: 'password is required'
    },
    cpassword:{
      type: String   
     
    },

    mobile:{
      type:"number"
    },

    dob:{
       type:"date"
    },

    gender:{
        type: String,
        enum:["Male","Female"]
         
    },

    profilePicture: {
      type: String,
      default: ""
    },
    bio:{
      type:String
    },
    
    isAdmin: {
      type: Boolean,
      default: false
    }, 
  },
  { timestamps: true }
);
function validateUser(user) {

const userValidation = (data) => {
  const complexityOptions = {
    min: 6,
    max: 250,
    numeric: 1,
    symbol: 1,
    requirementCount: 2
};

const schema = {
  firstname: Joi.string().min(4).required(),
  lastname: Joi.string().min(4).required(),
  email: Joi.string().email().min(6).required(),
  //password: Joi.string().min(6).numeric(1).required(),
  password: passwordComplexity(complexityOptions),
  cpassword: passwordComplexity(complexityOptions)
};

return Joi.validate(user, schema);
}
 
}

// exports.validate = validateUser;

module.exports = mongoose.model("User", UserSchema);
