import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import cors from "cors";
import admin from "firebase-admin";
// import serviceAccount from "./dev-notes-firebase-auth.json" assert { type: "json" };
import { getAuth } from "firebase-admin/auth";

// Schema
import User from "./Schema/User.js";

dotenv.config();
const server = express();

let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;

let PORT = 5000;

admin.initializeApp({
  credential: admin.credential.cert({
    type: process.env.TYPE,
    project_id: process.env.PROJECT_ID,
    private_key_id: process.env.PRIVATE_KEY_ID,
    private_key: process.env.PRIVATE_KEY.replace(/\\n/g, "\n"),
    client_email: process.env.CLIENT_EMAIL,
    client_id: process.env.CLIENT_ID,
    auth_uri: process.env.AUTH_URI,
    token_uri: process.env.TOKEN_URI,
    auth_provider_x509_cert_url: process.env.AUTH_PROVIDER_X509_CERT_URL,
    client_x509_cert_url: process.env.CLIENT_X509_CERT_URL,
  }),
  universe_domain: process.env.UNIVERSE_DOMAIN,
});

server.use(express.json());
server.use(cors());

mongoose.connect(process.env.DB_URI, {
  autoIndex: true,
});

const formatDataToSend = (user) => {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );
  return {
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
};

const generateUsername = async (email) => {
  let username = email.split("@")[0];

  const isUsernameExist = await User.exists({
    "personal_info.username": username,
  }).then((res) => res);

  isUsernameExist ? (username += nanoid().substring(0, 5)) : "";

  return username;
};

// sign up routes
server.post("/signup", async (req, res) => {
  let { fullname, email, password } = req.body;

  // validating data from frontend
  if (fullname.length < 3) {
    return res
      .status(403)
      .json({ error: "Full name should be at least 3 letters" });
  }

  if (!email.length) {
    return res.status(403).json({ error: "Email is required!" });
  }

  if (!emailRegex.test(email)) {
    return res.status(403).json({ error: "Email is not valid!" });
  }

  if (!passwordRegex.test(password)) {
    return res.status(403).json({
      error:
        "Password should be 6 to 20 characters long with a numeric, 1 lowercase and 1 uppercase letter",
    });
  }

  try {
    const existingUser = await User.findOne({ "personal_info.email": email });
    if (existingUser) {
      return res.status(403).json({ error: "Email already exists!" });
    }

    const hashed_password = await bcrypt.hash(password, 10);
    let username = await generateUsername(email);

    let user = new User({
      personal_info: {
        fullname,
        email,
        password: hashed_password,
        username,
      },
    });

    const savedUser = await user.save();
    return res.status(200).json(formatDataToSend(savedUser));
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// sign in routes
server.post("/signin", (req, res) => {
  let { email, password } = req.body;

  User.findOne({ "personal_info.email": email })
    .then((user) => {
      if (!user) {
        return res.status(403).json({ error: "Email not found" });
      }
      if (!user.google_auth) {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res.status(403).json({
              error: "Error is occured while login please try again later",
            });
          }
          if (!result) {
            return res.status(403).json({ error: "Incorrect password" });
          } else {
            return res.status(200).json(formatDataToSend(user));
          }
        });
      } else {
        return res.status(403).json({
          error: "Account was created with google. Try to logging with google",
        });
      }
    })
    .catch((err) => {
      return res.status(500).json({ error: err.message });
    });
});

// sign in with google
server.post("/google-auth", (req, res) => {
  let { access_token } = req.body;

  getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
      let { name, email, picture } = decodedUser;

      picture = picture.replace("s96-c", "s384-c");

      let user = await User.findOne({ "personal_info.email": email })
        .select(
          "personal_info.fullname personal_info.username personal_info.profile_img google_auth"
        )
        .then((u) => {
          return u || null;
        })
        .catch((err) => {
          return res.status(500).json({ error: err.message });
        });

      if (user) {
        // login
        if (!user.google_auth) {
          return res.status(403).json({
            error:
              "This email was signed up without google. Please login with password to access the account",
          });
        }
      } else {
        // sign up
        let username = await generateUsername(email);

        user = new User({
          personal_info: {
            fullname: name,
            email,
            profile_img: picture,
            username,
          },
          google_auth: true,
        });

        await user
          .save()
          .then((u) => {
            user = u;
          })
          .catch((err) => {
            return res.status(500).json({ error: err.message });
          });
      }
      return res.status(200).json(formatDataToSend(user));
    })
    .catch((err) => {
      console.log(err);
      return res.status(500).json({
        error:
          "Failed to authenticate you with google. Please try with another google account",
      });
    });
});

server.listen(PORT, () => {
  console.log("Listening on port", PORT);
});

// sign up routes
// server.post("/signup", (req, res) => {
//   let { fullname, email, password } = req.body;

//   // validating data from frontend
//   if (fullname.length < 3) {
//     return res
//       .status(403)
//       .json({ error: "Full name should be atleast 3 letters" });
//   }

//   if (!email.length) {
//     return res.status(403).json({ error: "Email is required!" });
//   }

//   if (!emailRegex.test(email)) {
//     return res.status(403).json({ error: "Email is not valid!" });
//   }

//   if (!passwordRegex.test(password)) {
//     return res.status(403).json({
//       error:
//         "Password should be 6 to 20 character long with a numeric, 1 lowercase and 1 uppercase leter",
//     });
//   }

//   bcrypt.hash(password, 10, async (err, hashed_password) => {
//     let username = await generateUsername(email);

//     let user = new User({
//       personal_info: {
//         fullname,
//         email,
//         password: hashed_password,
//         username,
//       },
//     });

//     user
//       .save()
//       .then((u) => {
//         return res.status(200).json(formatDataToSend(u));
//       })
//       .catch((err) => {
//         if (err.code === 11000) {
//           return res.status(500).json({ error: "Email already exists!" });
//         }
//         return res.status(500).json({ error: err.message });
//       });
//   });

//   // return res.status(200).json({ status: "okay" });
// });
