const db = require("../models");
const jwt = require("jsonwebtoken");
const config = require("../config/auth.config");
var bcrypt = require("bcryptjs");

const User = db.user;


exports.allAccess = async (req, res) => {
  res.status(200).send("All Access");
};

exports.userInfo = async (req, res) => {
  const token = req.header("x-access-token")
  jwt.verify(token, config.secret, (err,decodedToken) => {
    if(err) {
      res.status(500).send("Token Issue");
    } else {
      User.findOne({
        where: {
          id: decodedToken.id
        }
      })
        .then(user => {
          if (!user) {
            return res.status(404).send({ message: "User Not found." });
          }
          var authorities = [];
          user.getRoles().then(roles => {
            for (let i = 0; i < roles.length; i++) {
              authorities.push("ROLE_" + roles[i].name.toUpperCase());
            }
            res.status(200).send({
              id: user.id,
              username: user.username,
              email: user.email,
              roles: authorities,
              accessToken: token
            });
          });
        })
    }
  })
};