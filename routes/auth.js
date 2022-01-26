const express = require("express");
const router = express.Router();
const User = require("../models/User");
const { body, validationResult } = require("express-validator");
const bcrypt = require("bcryptjs");
var jwt = require("jsonwebtoken");
const fetchuser = require("../middleware/fetchuser");
const JWT_SECRET = "hellosourabh";
//ROUTE:1Create a user using POST '/api/auth/createuser' NO login required
router.post(
  "/createuser",
  [body("name").isLength({ min: 3 }), body("email").isEmail()],
  body("password").isLength({ min: 5 }),
  async (req, res) => {
    //   res.json([]);
    //     console.log(req.body);
    //     const user = User(req.body);
    //     user.save();
    //     res.send(req.body);
    //   }
    //if there are error return bad request
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    try {
      let user = await User.findOne({ email: req.body.email });
      if (user) {
        return res
          .status(400)
          .json({ error: "sorry the user with this email already present" });
      }
      const salt = await bcrypt.genSalt(10);
      const secPass = await bcrypt.hash(req.body.password, salt);
      user = await User.create({
        name: req.body.name,
        password: secPass,
        email: req.body.email,
      });
      const data = {
        user: {
          id: user.id,
        },
      };
      const authToken = jwt.sign(data, JWT_SECRET);
      // .then((user) => res.json(user));
      res.json({ authToken });
    } catch (error) {
      console.error(error.message);
      res.status(500).send("Internal server error ");
    }
  }
);
//ROUTE:2authenticate a user using POST '/api/auth/login' NO login required
router.post(
  "/login",
  [
    body("email", "Enter the valid email").isEmail(),
    body("password", "Enter the valid password").exists(),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;
    try {
      let user = await User.findOne({ email });
      if (!user) {
        return res
          .status(404)
          .json({ error: "Please try to login with correct credentials" });
      }
      const passwordCompare = await bcrypt.compare(password, user.password);
      if (!passwordCompare) {
        return res
          .status(404)
          .json({ error: "Please try to login with correct credentials" });
      }
      const data = {
        user: { id: user.id },
      };
      const authToken = jwt.sign(data, "JWT_SECRET");
      // .then((user) => res.json(user));
      res.json({ authToken });
    } catch (error) {
      console.error(error.message);
      res.status(500).send("Internal server error ");
    }
  }
);

//ROUTE:3Get login user details using POST '/api/auth/getuser' login required
router.post("/getuser", fetchuser, async (req, res) => {
  try {
    const userId = req.user.id;
    const user = await User.findById(userId).select("-password");
    res.send(user);
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Internal server error ");
  }
});
module.exports = router;
