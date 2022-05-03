const router = require("express").Router();
const Post = require("../models/Post");
const User = require("../models/User");
const jwt =require("jsonwebtoken");
const upload =require("../middleware/upload");



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
      console.log(user)
      next();
    });
  } else {
    res.status(401).json("You are not authenticated!");
  }
};
//create a post
console.log(Post)
console.log(User)
router.post("/", upload.single("image"), async (req, res) => {
  const newPost = new Post({
    desc:req.body.desc,
    userId:req.body.userId,
    img:req.file.path
  });
  try {
    const savedPost = await newPost.save();
    res.status(200).json(savedPost);
  } catch (err) {
    res.status(500).json(err);
  }
});
//update a post

router.put("/update/:id",verify, async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    console.log(req.user.id)
    console.log(req.body.userId)
    if (req.user.id === req.body.userId) {
      await post.updateOne({ $set: req.body });
      res.status(200).json("the post has been updated");
    } else {
      res.status(403).json("you can update only your post");
    }
  } catch (err) {
    res.status(500).json(err);
  }
});
//delete a post
router.delete("/del/:id",verify, async (req, res) => {
  console.log("hello")
  try {
    const post = await Post.findById(req.params.id);
    console.log(req.user.id)
    console.log(req.body.userId)

    if (req.user.id === req.body.userId) {
      
      await post.deleteOne();
      res.status(200).json("the post has been deleted");
    } else {
      res.status(403).json("you can delete only your post");
    }
  } catch (err) {
    res.status(500).json(err);
  }
});
//comments
router.put("/:id/comments", async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
      let comment={userId:req.body.userId,comment:req.body.comment}
      console.log(comment)
      await post.updateOne({ $push: {comments:comment}} );
    const post1 = await Post.findById(req.params.id)
      res.status(200).json(post1);
   
  } catch (err) {
    res.status(500).json(err);
  }
});
//like / dislike a post

router.put("/:id/like", async (req, res) => {
  console.log(req.body)
  try {
    const post = await Post.findById(req.params.id);
    const user =await User.findById(req.body.userId);
    console.log(post);
    if (user){
    if (!post.likes.includes(req.body.userId)) {
      console.log(req.body.userId)
      await post.updateOne({ $push: { likes: req.body.userId } });
      const post1 = await Post.findById(req.params.id)
      res.status(200).json({post:post1._doc,message:"The post has been liked"});
    } else {
      console.log("hello")
      await post.updateOne({ $pull: { likes: req.body.userId } });
      const post1 = await Post.findById(req.params.id)

      res.status(200).json({post:post1._doc,message:"The post has been disliked"});
    }
    }else{
      res.status(200).json("user is not valid");

    }
  } catch (err) {
    res.status(500).json(err);
  }
});
//get a post

router.get("/:id", async (req, res) => {
  try {
    const post = await Post.findById(req.params.id);
    res.status(200).json(post);
  } catch (err) {
    res.status(500).json(err);
  }
});

//get timeline posts

router.get("/timeline/allPosts", async (req, res) => {
  try {
    let posts=await Post.find()
  //  await Post.find({}, function (err, post) {
  //     posts[post._id] = post;
  // });
    
    console.log(posts)
    res.status(200).json(posts);
  } catch (err) {
    res.status(500).json(err);
  }
});
// router.get("/timeline/:userId", async (req, res) => {
//   try {
//     const currentUser = await User.findById(req.params.userId);
//     const userPosts = await Post.find({ userId: currentUser._id });
//     const friendPosts = await Promise.all(
//       currentUser.followings.map((friendId) => {
//         return Post.find({ userId: friendId });
//       })
//     );
//     res.status(200).json(userPosts.concat(...friendPosts));
//   } catch (err) {
//     res.status(500).json(err);
//   }
// });

//get user's all posts



//-----------------------------pagination-------------------------------
router.get('/pos/update', paginatedResults(Post), (req, res) => {
  res.json(res.paginatedResults)
})

function paginatedResults(model) {

  return async (req, res, next) => {
    console.log(req.query.page)
    const page = parseInt(req.query.page)
    const limit = parseInt(req.query.limit)

    const startIndex = (page - 1) * limit
    const endIndex = page * limit

    const results = {}

    if (endIndex < await model.countDocuments().exec()) {
      results.next = {
        page: page + 1,
        limit: limit
      }
    }
    
    if (startIndex > 0) {
      results.previous = {
        page: page - 1,
        limit: limit
      }
    }
    try {
      results.results = await model.find().limit(limit).skip(startIndex).exec()
      res.paginatedResults = results
      next()
    } catch (e) {
      res.status(500).json({ message: e.message })
    }
  }
}
module.exports = router;
