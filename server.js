import express from "express";
import mongoose from "mongoose";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import "dotenv/config.js";
import bcrypt from "bcryptjs";
import bodyParser from "body-parser";

import admin from "firebase-admin";
import serviceAccountKey from "./bloom-blogging-firebase-adminsdk.json" assert { type: "json" };
import { getAuth } from "firebase-admin/auth";

//Schemas
import User from "./Schema/User.js";
import Blog from "./Schema/Blog.js";
import Notification from "./Schema/Notification.js";
import Comment from "./Schema/Comment.js";

//regex
let emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/; // regex for email
let passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/; // regex for password

//mongoose db
mongoose.connect(process.env.DB_LOCATION, {
  autoIndex: true,
});

let app =
  admin.apps.length == 0
    ? admin.initializeApp({
        credential: admin.credential.cert(serviceAccountKey),
      })
    : admin.apps[0];

const server = express();
const PORT = 4000;

server.use(express.json());
server.use(bodyParser.urlencoded({ extended: true }));

//additional functions
async function generateUsername(email) {
  let username = email.split("@")[0];
  const isUserExists = await User.exists({
    personal_info: { username: username },
  }).then((res) => res);

  isUserExists ? (username += nanoid().substring(0, 5)) : "";
  return username;
}

function formatDataToSend(user) {
  const access_token = jwt.sign(
    { id: user._id },
    process.env.SECRET_ACCESS_KEY
  );
  return {
    status: 200,
    access_token,
    profile_img: user.personal_info.profile_img,
    username: user.personal_info.username,
    fullname: user.personal_info.fullname,
  };
}

function tokenVerify(req, res, next) {
  const authHeaders = req.headers["authorization"];
  const token = authHeaders && authHeaders.split(" ")[1];

  if (token == null) {
    return res.status(401).json({ status: 500, error: "No access token" });
  }

  jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) => {
    if (err) {
      return res.status(500).json({
        status: 500,
        message: "Access token is invalid",
        error: err.message,
      });
    }
    req.body.user_id = user.id;
    next();
  });
}

server.post("/credValidityCheck", async (req, res) => {
  console.log("body =>", req.body);
  let { type, username, email, password } = req.body;

  if (type == "signup") {
    if (!username.length || username.length < 4) {
      return {
        status: "befSub",
        error: "Enter username with a minimum of 4 characters to continue.",
      };
    }
  }

  if (!email.length || !emailRegex.test(email)) {
    return { status: "befSub", error: "Email is invalid" };
  }

  if (!password.length || !passwordRegex.test(password)) {
    return {
      status: "befSub",
      error:
        "Password is invalid. Password must be 6 to 20 characters long with numbers and 1 lowercase and 1 uppercase letters.",
    };
  }

  if (type == "signup") {
    const hashResponse = await new Promise((resolve, reject) => {
      bcrypt.hash(password, 10, async (err, hashed_pass) => {
        if (err) resolve({ status: 500, error: "Sorry, error ocurred." });
        const generatedUsername = await generateUsername(email);
        const user = new User({
          personal_info: {
            fullname: username,
            email,
            password: hashed_pass,
            username: generatedUsername,
          },
        });

        user
          .save()
          .then((u) => {
            resolve({ status: 200, ...u._doc });
          })
          .catch((err) => {
            if (err.code == 11000) {
              console.error("error");
              resolve({ status: 403, error: "Email already exists" });
            } else {
              resolve({ status: 500, error: err });
            }
          });
      });
    });

    if (hashResponse.status == 200) {
      return res.status(200).json(formatDataToSend(hashResponse));
    }

    return res.status(hashResponse.status).json(hashResponse);
  }

  if (type == "signin") {
    User.findOne({
      "personal_info.email": email,
    })
      .then((user) => {
        if (!user) {
          return res
            .status(500)
            .json({ status: "404", error: "Email not found.", ...user });
        }

        // const passCheck = new Promise((resolve, reject) => {
        bcrypt.compare(password, user.personal_info.password, (err, result) => {
          if (err) {
            return res.status(500).json({ status: 500, error: err.message });
          }

          if (!result) {
            return res
              .status(405)
              .json({ status: 405, error: "Password is wrong" });
          } else {
            return res.status(200).json(formatDataToSend({ ...user._doc }));
          }
        });
        // });

        // return passCheck;
      })
      .catch((err) => {
        console.log(err);
        return res.status(404).json({ status: 404, error: err.message });
      });
    // console.log(result);

    // if (result.status == 200) {
    //   return res.status(200).json(formatDataToSend(result));
    // }
    // return result;
  }
});

server.post("/googleAuth", async (req, res) => {
  console.log("gbody =>", req.body);
  let { access_token } = req.body;

  // const result = await
  getAuth(app)
    .verifyIdToken(access_token)
    .then(async (decodedUser) => {
      let { email, name, picture } = decodedUser;

      picture = picture.replace("s96-c", "s384-c");

      let user = await User.findOne({ "personal_info.email": email })
        .select(
          "personal_info.profile_img personal_info.fullname personal_info.username google_auth"
        )
        .then((u) => {
          return u || null;
        })
        .catch((err) => {
          console.error("Error while finding the user in DB for google auth.");
          console.error(err);
          return "error";
        });

      if (user && user != "error") {
        if (!user.google_auth) {
          return res.status(403).json({
            status: 403,
            error:
              "This account was already signed up with password. Please log in with password to use this account.",
          });
        }
      } else {
        let username = await generateUsername(email);

        user = new User({
          personal_info: {
            fullname: name,
            email,
            username: username,
          },
          google_auth: true,
        });

        await user
          .save()
          .then((u) => {
            user = { status: 200, ...u };
          })
          .catch((err) => {
            console.error(
              "Error while saving the user from google account in DB"
            );
            console.error(err.message);
            return res.status(500).json({
              status: 500,
              error: "Trouble signing with Google account, try again later.",
            });
          });
      }

      if (user.status == 200) {
        // console.log(formatDataToSend(user));
        return res.status(200).json(formatDataToSend(user));
      } else if (user.status == 403) {
        // console.log({ status: 500, error: user.error });
        return res.status(403).json({ status: 500, error: user.error });
      } else if (user.status == 500) {
        // console.log({ status: 500 });
        return res.status(500).json({
          status: 500,
          error: "Trouble signing with Google account, try again later.",
        });
      } else {
        // console.log(formatDataToSend(user));
        return res.status(200).json(formatDataToSend(user));
      }
    })
    .catch((err) => {
      console.log(err);
      return res
        .status(500)
        .json({ status: 500, error: "Failed to authenticate with Google" });
    });
  // return result;
});

server.post("/getBlog", (req, res) => {
  console.log("gb");
  let { blog_id, mode, draft } = req.body;

  let incrementalVal = mode != "edit" ? 1 : 0;

  // const result = await
  Blog.findOneAndUpdate(
    { blog_id },
    { $inc: { "activity.total_reads": incrementalVal } }
  )
    .populate(
      "author",
      "personal_info.fullname personal_info.username personal_info.profile_img"
    )
    .lean()
    .select("title des content banner activity publishedAt blog_id tags")
    .then(async (blog) => {
      // const readUpdateResult =
      await User.findOneAndUpdate(
        { "personal_info.username": blog.author.personal_info.username },
        { $inc: { "account_info.total_reads": incrementalVal } }
      )
        .then(() => {
          return res.status(200).json({ status: 200, blog });
        })
        .catch((err) => {
          return res.status(500).json({
            status: 500,
            message: "Can't connect to the server",
            error: err.message,
          });
        });

      if (blog.draft && !draft) {
        return res.status(500).json({
          status: 500,
          message: "You can't access drafted blogs",
          error:
            "You cannot access a drafted blog to edit by using this method",
        });
      }

      // if (readUpdateResult.status == 200) {
      //   return { status: 200, blog };
      // } else {
      //   return readUpdateResult;
      // }
    })
    .catch((err) => {
      return res.status(500).json({
        status: 500,
        message: "Can't connect to the server",
        error: err.message,
      });
    });

  // return result;
});

server.post("/searchBlogs", (req, res) => {
  console.log("sb");
  let { author, limit, query, tag, page = 1, eliminate_blog } = req.body;

  let maxLimit = limit ? limit : 5;
  let findQuery;

  if (tag) {
    findQuery = {
      tags: tag,
      draft: false,
      blog_id: { $ne: eliminate_blog },
    };
  } else if (query) {
    findQuery = { draft: false, title: new RegExp(query, "i") };
  } else if (author) {
    findQuery = { draft: false, author: author };
  }

  Blog.find(findQuery)
    .populate(
      "author",
      "personal_info.profile_img personal_info.fullname personal_info.username -_id"
    )
    .lean()
    .sort({ publishedAt: -1 })
    .select("blog_id title des banner tags activity publishedAt -_id")
    .skip(maxLimit * (page - 1))
    .limit(maxLimit)
    .then((blogs) => {
      return res.status(200).json({ status: 200, blogs: blogs });
    })
    .catch((err) => {
      return res.status(500).json({
        status: 500,
        message: "Can't connect to the server",
        error: err.message,
      });
    });
});

server.post("/getUserWrittenBlogs", tokenVerify, (req, res) => {
  let { page, draft, query, deletedDocCount, user_id } = req.body;

  let maxLimit = 5;
  let skipDocs = (page - 1) * maxLimit;

  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }

  Blog.find({
    author: user_id,
    draft,
    title: new RegExp(query, "i"),
  })
    .skip(skipDocs)
    .limit(maxLimit)
    .sort({ publishedAt: -1 })
    .select("title banner publishedAt blog_id activity des draft -_id")
    .then((blogs) => {
      // console.log("blogs =>", blogs);
      return res.status(200).json({ status: 200, blogs });
    })
    .catch((err) => {
      return res.status(500).json({
        status: 500,
        message: "Failed to retrieve your blogs",
        error: err.message,
      });
    });
});

server.post("/getNotifications", tokenVerify, (req, res) => {
  let { user_id, page, filter, deletedDocCount } = req.body;

  let maxLimit = 10;

  let findQuery = { notification_for: user_id, user: { $ne: user_id } };
  let skipDocs = (page - 1) * maxLimit;

  if (filter != "all") {
    findQuery.type = filter;
  }

  if (deletedDocCount) {
    skipDocs -= deletedDocCount;
  }

  Notification.find(findQuery)
    .skip(skipDocs)
    .limit(maxLimit)
    .populate("blog", "title blog_id")
    .lean()
    .populate(
      "user",
      "personal_info.fullname personal_info.username personal_info.profile_img"
    )
    .lean()
    .populate("comment", "comment")
    .lean()
    .populate("replied_on_comment", "comment")
    .lean()
    .populate("reply", "comment")
    .lean()
    .sort({ createdAt: -1 })
    .select("createdAt type seen reply ")
    .then((notifications) => {
      return res.status(200).json({ status: 200, notifications });
    })
    .catch((err) => {
      console.error(err.message);
      return res.status(500).json({
        status: 500,
        error: err.message,
        message: "failed to get notifications data",
      });
    });
});

server.post("/getBlog", (req, res) => {
  let { user_id, blog_id, mode, draft } = req.body;

  let incrementalVal = mode != "edit" ? 1 : 0;

  Blog.findOneAndUpdate(
    { blog_id },
    { $inc: { "activity.total_reads": incrementalVal } }
  )
    .populate(
      "author",
      "personal_info.fullname personal_info.username personal_info.profile_img"
    )
    .lean()
    .select("title des content banner activity publishedAt blog_id tags")
    .then(async (blog) => {
      // const readUpdateResult = await
      User.findOneAndUpdate(
        { "personal_info.username": blog.author.personal_info.username },
        { $inc: { "account_info.total_reads": incrementalVal } }
      )
        .then(() => {
          return res.status(200).json({ status: 200, blog });
        })
        .catch((err) => {
          return res.status(500).json({
            status: 500,
            message: "Can't connect to the server",
            error: err.message,
          });
        });

      if (blog.draft && !draft) {
        return res.status(500).json({
          status: 500,
          message: "You can't access drafted blogs",
          error:
            "You cannot access a drafted blog to edit by using this method",
        });
      }
      // if (readUpdateResult.status == 200) {
      //   return { status: 200, blog };
      // } else {
      //   return readUpdateResult;
      // }
    })
    .catch((err) => {
      return res.status(500).json({
        status: 500,
        message: "Can't connect to the server",
        error: err.message,
      });
    });
});

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
