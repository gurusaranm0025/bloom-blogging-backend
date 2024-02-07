import express from "express";
import mongoose from "mongoose";
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken";
import "dotenv/config.js";
import bcrypt from "bcryptjs";
import bodyParser from "body-parser";
import cors from "cors";
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
server.use(cors());

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

server.post("/searchUsers", (req, res) => {
  let { query } = req.body;

  User.find({
    "personal_info.username": new RegExp(query, "i"),
  })
    .limit(50)
    .select(
      "personal_info.username personal_info.fullname personal_info.profile_img -_id"
    )
    .then((users) => {
      return res.status(200).json({ status: 200, users });
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

server.post("/createBlog", tokenVerify, (req, res) => {
  console.log("cbb =>", req.body);
  let { user_id: authorId, blogContent } = req.body;

  let { title, des, banner, tags, content, draft, id } = blogContent;

  if (!title.length)
    return {
      status: 500,
      message: "Give a title to upload.",
      error: "you should give a title to publish your blog.",
    };

  if (!draft) {
    if (!des.length || des.length > 200)
      return res.status(500).json({
        status: 500,
        message:
          "You must provide a blog description which is less than 200 characters",
        error:
          "You must give your blog a description and it should contain less than 200 characters.",
      });

    if (!banner.length)
      return res.status(500).json({
        status: 500,
        message: "You must provide a blog banner to continue",
        error: "You must give your blog a banner image to publish it.",
      });

    if (!content.blocks.length)
      return res.status(500).json({
        status: 500,
        message: "There are no content in the blog to publish it.",
        error:
          "You must write something in your blog to publish it, we can't just allow you to publish nothing now, right!",
      });

    if (!tags.length || tags.length > 10)
      return res.status(500).json({
        status: 500,
        message: "Please provide tags (maximum 10 tags are allowed)",
        error:
          "Give your blog some tags, which helps us to optimize search results to show your blog in searches.",
      });
  }

  tags = tags.map((tag) => tag.toLowerCase());

  let blog_id =
    id ||
    title
      .replace(/[^a-zA-Z0-9]/g, " ")
      .replace(/\s+/g, "-")
      .trim() + nanoid();

  if (id) {
    // const blogUpdateResult = await
    Blog.findOneAndUpdate(
      { blog_id },
      { title, des, banner, content, tags, draft: Boolean(draft) }
    )
      .then((data) => {
        return res.status(200).json({ status: 200, id: data.blog_id });
      })
      .catch((err) => {
        return res.status(500).json({
          status: 500,
          message: "Failed to update the blog.",
          error: err.message,
        });
      });

    // return blogUpdateResult;
  } else {
    let blog = new Blog({
      title,
      des,
      banner,
      content,
      tags,
      author: authorId,
      blog_id,
      draft: Boolean(draft),
    });

    // const blogPublishResult = await
    blog
      .save()
      .then(async (blog) => {
        let incrementVal = draft ? 0 : 1;
        // const findUpdateResult = await
        User.findOneAndUpdate(
          { _id: authorId },
          {
            $inc: { "account_info.total_posts": incrementVal },
            $push: { blogs: blog._id },
          }
        )
          .then((user) => {
            return res.status(200).json({ status: 200, message: blog.blog_id });
          })
          .catch((err) => {
            console.error(err.message);
            return res.status(500).json({
              status: 500,
              message: "Failed to update total number of posts",
              error: err.message,
            });
          });

        // return findUpdateResult;
      })
      .catch((err) => {
        console.error(err.message);
        return res.status(500).json({
          status: 500,
          message: "Failed to publish blog",
          error: err.message,
        });
      });

    // blogPublishResult.status == 500 ? console.log(blogPublishResult) : "";
    // return blogPublishResult;
  }
});

server.post("/changePassword", tokenVerify, (req, res) => {
  let { currentPassword, newPassword, user_id } = req.body;

  if (
    !passwordRegex.test(currentPassword) ||
    !passwordRegex.test(newPassword)
  ) {
    return res.status(500).json({
      status: 500,
      message:
        "Password is invalid. Password must be 6 to 20 characters long with numbers and 1 lowercase and 1 uppercase letters.",
      error:
        "Password is invalid. Password must be 6 to 20 characters long with numbers and 1 lowercase and 1 uppercase letters.",
    });
  }

  User.findOne({ _id: user_id })
    .then(async (user) => {
      if (user.google_auth) {
        return res.status(500).json({
          status: 500,
          message:
            "You can't change the password of an account created using Google account",
          error:
            "Since you've used Google account to create your account, you can't change the password.",
        });
      }

      // let passCheckResult = await new Promise((resolve, reject) => {
      bcrypt.compare(
        currentPassword,
        user.personal_info.password,
        async (err, result) => {
          if (err) {
            return res.status(500).json({
              status: 500,
              message: "Error occured while checking the current password.",
              error:
                "It seems like our service had faced some error while checking your password. ",
            });
          }

          if (!result) {
            return res.status(500).json({
              status: 500,
              error: "You current password is wrong",
              message: "Your current password id wrong.",
            });
          }

          bcrypt.hash(newPassword, 10, (err, hashedPass) => {
            User.findOneAndUpdate(
              { _id: user_id },
              { "personal_info.password": hashedPass }
            )
              .then((user) => {
                return res
                  .status(200)
                  .json({ status: 200, message: "Password is changed" });
              })
              .catch((err) => {
                return res.status(500).json({
                  status: 500,
                  message:
                    "Error occurred while changing the password. Please, try again later",
                  error: err.message,
                });
              });
          });
        }
      );

      // });

      // return passCheckResult;
    })
    .catch((err) => {
      return res
        .status(500)
        .json({ status: 500, message: "User not found", error: err.message });
    });
});

server.post("/getUserProfile", (req, res) => {
  let { username } = req.body;

  User.findOne({
    "personal_info.username": username,
  })
    .select("-personal_info.password -google_auth -updatedAt -blogs")
    .then((user) => {
      return res.status(200).json({ status: 200, user });
    })
    .catch((err) => {
      return res.status(500).json({
        status: 500,
        message: "Error occurred while finding the user",
        error: err.message,
      });
    });
});

server.post("/updateProfileImage", tokenVerify, (req, res) => {
  let { user_id, url } = req.body;

  User.findOneAndUpdate({ _id: user_id }, { "personal_info.profile_img": url })
    .then(() => {
      return res.status(200).json({
        status: 200,
        message: "Profile image is updated",
        profile_img: url,
      });
    })
    .catch((err) => {
      return res.status(500).json({
        status: 500,
        message: "Error occurred while updating the image",
        error: err.message,
      });
    });
});

server.post("/updateProfile", tokenVerify, (req, res) => {
  let { user_id, username, bio, social_links } = req.body;

  if (!username.length || username.length < 4) {
    return res.status(500).json({
      status: "500",
      message: "Enter username with a minimum of 4 characters to continue.",
      error: "Enter username with a minimum of 4 characters to continue.",
    });
  }

  if (bio.length > 150) {
    return res.status(500).json({
      status: "500",
      message: "Bio should not contain more than 150 character",
      error: "Bio should not contain more than 150 character",
    });
  }

  let socialLinksArr = Object.keys(social_links);

  try {
    for (let i = 0; i < socialLinksArr.length; i++) {
      if (social_links[socialLinksArr[i]].length) {
        let hostname = new URL(social_links[socialLinksArr[i]]).hostname;

        if (
          !hostname.includes(`${socialLinksArr[i]}.com`) &&
          socialLinksArr[i] != "website"
        ) {
          return res.status(500).json({
            status: 500,
            message: `${socialLinksArr[i]} link is invalid`,
            error:
              "Invalid links are provided as input for social links field.",
          });
        }
      }
    }
  } catch (err) {
    return res.status(500).json({
      status: 500,
      message: "You must provide full social links with 'https' included.",
      error: "You must provide full social links with 'https' included.",
    });
  }

  let updateObj = {
    "personal_info.username": username,
    "personal_info.bio": bio,
    social_links,
  };

  User.findOneAndUpdate({ _id: user_id }, updateObj, {
    runValidators: true,
  })
    .then((response) => {
      return res.status(200).json({ status: 200, username });
    })
    .catch((err) => {
      if (err.code == 11000) {
        return res.status(500).json({
          status: 500,
          message: "Username is already taken",
          error: err.message,
        });
      } else {
        return res.status(500).json({
          status: 500,
          message: "Error occurred while updating the profile",
          error: err.message,
        });
      }
    });
});

server.post("/getLatestBlogs", (req, res) => {
  let { page = 1 } = req.body;

  let maxLimit = 5;

  Blog.find({ draft: false })
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

server.post("/getTrendingBlogs", (req, res) => {
  Blog.find({ draft: false })
    .populate(
      "author",
      "personal_info.profile_img personal_info.fullname personal_info.username -_id"
    )
    .lean()
    .sort({
      "activity.total_reads": -1,
      "activity.total_likes": -1,
      publishedAt: -1,
    })
    .select("blog_id title publishedAt -_id")
    .limit(5)
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

server.post("/getIsLikedByUser", tokenVerify, (req, res) => {
  let { user_id, _id } = req.body;

  Notification.exists({
    user: user_id,
    type: "like",
    blog: _id,
  })
    .then((response) => {
      return res.status(200).json({ status: 200, result: response });
    })
    .catch((err) => {
      return res.status(500).json({
        status: 500,
        message: "Can't connect to the server",
        error: err.message,
      });
    });
});

server.post("/likeBlog", tokenVerify, (req, res) => {
  let { user_id, _id, isLikedByUser } = req.body;

  let incrementalVal = !isLikedByUser ? 1 : -1;

  Blog.findOneAndUpdate(
    { _id },
    { $inc: { "activity.total_likes": incrementalVal } }
  ).then(async (blog) => {
    if (!isLikedByUser) {
      let like = new Notification({
        type: "like",
        blog: _id,
        notification_for: blog.author,
        user: user_id,
      });

      // const likeNotificationResult = await
      like
        .save()
        .then((notification) => {
          return res.status(200).json({ status: 200, likedByUser: true });
        })
        .catch((err) => {
          return res.status(500).json({
            status: 500,
            message: "Can't connect to the server",
            error: err.message,
          });
        });

      // return likeNotificationResult;
    } else {
      // const dislikeResult = await
      Notification.findOneAndDelete({
        user: user_id,
        blog: _id,
        type: "like",
      })
        .then((data) => {
          return res.status(200).json({ status: 200, likedByUser: false });
        })
        .catch((err) => {
          return res.status(500).json({
            status: 500,
            message: "Can't connect to the server",
            error: err.message,
          });
        });

      // return dislikeResult;
    }
  });
});

server.post("/getReplies", (req, res) => {
  let { _id, skip } = req.body;

  let maxLimit = 5;

  Comment.findOne({ _id })
    .populate({
      path: "children",
      options: {
        lean: true,
        limit: maxLimit,
        skip: skip,
        sort: { commentedAt: -1 },
      },
      populate: {
        path: "commented_by",
        option: { lean: true },
        select:
          "personal_info.profile_img personal_info.username personal_info.fullname",
      },
      select: "-blog_id -updatedAt",
    })
    .lean()
    .select("children")
    .then((doc) => {
      return res.status(200).json({ status: 200, replies: doc.children });
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({
        status: 500,
        message: "Can't connect to server",
        error: err.message,
      });
    });
});

function deleteComments(_id) {
  Comment.findOneAndDelete({ _id })
    .then(async (comment) => {
      if (comment.parent) {
        Comment.findOneAndUpdate(
          { _id: comment.parent },
          { $pull: { children: _id } }
        )
          .then((data) => {
            console.log("COmment is deleted from parent");
          })
          .catch((err) => {
            console.log(err.message);
          });
      }

      Notification.findOneAndDelete({ comment: _id }).then((notification) =>
        console.log("comment's notification is deleted")
      );

      Notification.findOneAndUpdate(
        { reply: _id },
        { $unset: { reply: 1 } }
      ).then((notification) => console.log("reply's notification is deleted"));

      Blog.findOneAndUpdate(
        { _id: comment.blog_id },
        {
          $pull: { comments: _id },
          $inc: {
            "activity.total_comments": -1,
            "activity.total_parent_comments": comment.parent ? 0 : -1,
          },
        }
      ).then((blog) => {
        if (comment.children.length) {
          comment.children.map((replies) => {
            deleteComments(replies);
          });
        }
      });
    })
    .catch((err) => {
      console.log(err.message);
    });
}

server.post("/deleteComment", tokenVerify, (req, res) => {
  let { user_id, _id } = req.body;

  Comment.findOne({ _id }).then((comment) => {
    if (user_id == comment.commented_by || user_id == comment.blog_author) {
      deleteComments(_id);
      return res
        .status(200)
        .json({ status: 200, message: "The comment or message is deleted" });
    } else {
      return res.status(500).json({
        status: 500,
        message: "You can't delete this comment or reply",
        error:
          "Only the author of the comment or reply or the author of the blog is allowed to delete.",
      });
    }
  });
});

server.post("/addComment", tokenVerify, (req, res) => {
  let { _id, comment, replying_to, blog_author, notification_id, user_id } =
    req.body;

  if (!comment.length) {
    return res.status(500).json({
      status: 500,
      message: "Write something to comment.",
      error: "Sorry, we cannot send empty message as comments.",
    });
  }

  //creating a comment doc
  let commentObj = {
    blog_id: _id,
    blog_author,
    comment,
    commented_by: user_id,
  };

  if (replying_to) {
    commentObj.parent = replying_to;
    commentObj.isReply = true;
  }

  new Comment(commentObj).save().then(async (commentFile) => {
    let { comment, commentedAt, children } = commentFile;

    await Blog.findByIdAndUpdate(
      { _id },
      {
        $push: { comments: commentFile._id },
        $inc: {
          "activity.total_comments": 1,
          "activity.total_parent_comments": replying_to ? 0 : 1,
        },
      }
    )
      .then(() => {
        console.log("New comment created.");
      })
      .catch((err) => {
        console.log(err.message);
      });

    let notificationObj = {
      type: replying_to ? "reply" : "comment",
      blog: _id,
      notification_for: blog_author,
      user: user_id,
      comment: commentFile._id,
    };

    if (replying_to) {
      notificationObj.replied_on_comment = replying_to;

      await Comment.findOneAndUpdate(
        { _id: replying_to },
        { $push: { children: commentFile._id } }
      ).then((replyingToCommentDoc) => {
        notificationObj.notification_for = replyingToCommentDoc.commented_by;
      });

      if (notification_id) {
        Notification.findOneAndUpdate(
          { _id: notification_id },
          { reply: commentFile._id }
        ).then((notification) => {
          console.log("Notification is updated...");
        });
      }
    }

    await new Notification(notificationObj)
      .save()
      .then((notification) => {
        console.log("new notification created");
      })
      .catch((err) => {
        console.error(err.message);
      });

    return res.status(200).json({
      status: 200,
      comment,
      commentedAt,
      _id: commentFile._id,
      user_id,
      children,
    });
  });
});

server.post("/getBlogComments", (req, res) => {
  let { blog_id, skip } = req.body;

  let maxLimit = 5;

  Comment.find({ blog_id, isReply: false })
    .populate(
      "commented_by",
      "personal_info.username personal_info.fullname personal_info.profile_img"
    )
    .lean()
    .skip(skip)
    .limit(maxLimit)
    .sort({ commentedAt: -1 })
    .then((comments) => {
      return res.status(200).json({ status: 200, comments });
    })
    .catch((err) => {
      console.log(err.message);
      return res.status(500).json({
        status: 500,
        message: "Can't connect to the server",
        error: err.message,
      });
    });
});

export async function tokVerify({ token }) {
  const tokenResult = jwt.verify(
    token,
    process.env.SECRET_ACCESS_KEY,
    (err, user) => {
      if (err) {
        return {
          status: 500,
          message: "Access token is invalid",
          error: err.message,
        };
      }
      return { status: 200, message: "Token is valid", id: user.id };
    }
  );

  return tokenResult;
}

export async function userWrittenBlogsCount({ token, draft, query }) {
  let user_id;

  let tokenResult = await tokVerify({ token });
  if (tokenResult.status == 200) {
    user_id = tokenResult.id;
  } else {
    return tokenResult;
  }

  const result = await Blog.countDocuments({
    author: user_id,
    draft,
    title: new RegExp(query, "i"),
  })
    .then((count) => {
      return { status: 200, totalDocs: count };
    })
    .catch((err) => {
      console.error(err.message);
      return {
        status: 500,
        message:
          "An error occured while retrieving number of blogs written by you.",
        error: err.message,
      };
    });

  return result;
}

export async function allNotificationCount({ token, filter }) {
  let user_id;

  let tokenResult = await tokVerify({ token });

  if (tokenResult.status == 200) {
    user_id = tokenResult.id;
  } else {
    return tokenResult;
  }

  let findQuery = { notification_for: user_id, user: { $ne: user_id } };

  if (filter != "all") {
    findQuery.type = filter;
  }

  const result = await Notification.countDocuments(findQuery)
    .then((count) => {
      return { status: 200, totalDocsKey: count };
    })
    .catch((err) => {
      console.error(err.message);
      return {
        status: 500,
        message: "Failed to get number of notifications",
        error: err.message,
      };
    });

  console.log("Notification counts:::::::::::::;;");
  console.log(result);

  return result;
}

server.post("/blogsCount", async (req, res) => {
  let { route, category } = req.body;

  let result;
  let findQuery;
  if (route == "latest") {
    findQuery = { draft: false };
  } else if (route == "category") {
    findQuery = { draft: false, tags: category.tag };
  } else if (route == "searchByQuery") {
    findQuery = { draft: false, title: new RegExp(category.query, "i") };
  } else if (route == "notifications") {
    result = await allNotificationCount({
      token: category.user,
      filter: category.filter,
    });
    if (result && result.status == 200) {
      return res.status(200).json(result);
    } else {
      return res.status(500).json(result);
    }
  } else if (route == "user-written-blogs-count") {
    result = await userWrittenBlogsCount({
      token: category.user,
      draft: category.draft,
      query: category.query,
    });
    if (result && result.status == 200) {
      return res.status(200).json(result);
    } else {
      return res.status(500).json(result);
    }
  }

  if (route != "notifications" && route != "user-written-blogs-count") {
    Blog.countDocuments(findQuery)
      .then((count) => {
        return res.status(200).json({ status: 200, totalDocs: count });
      })
      .catch((err) => {
        return res.status(500).json({
          status: 500,
          message: "Can't connect to the server",
          error: err.message,
        });
      });
  }
});

server.post("/deleteBlog", tokenVerify, (req, res) => {
  let { user_id, blog_id } = req.body;

  Blog.findOneAndDelete({ blog_id })
    .then((blog) => {
      Notification.deleteMany({ blog: blog._id }).then((data) => {
        console.log("Notifications are deleted.");
      });

      Comment.deleteMany({ blog_id }).then((data) => {
        console.log("comments are deleted");
      });

      User.findOneAndUpdate(
        { _id: user_id },
        { $pull: { blog: blog._id }, $inc: { "account_info.total_posts": -1 } }
      ).then((data) => {
        console.log("Blog is deleted.");
      });

      return res
        .status(200)
        .json({ status: 200, message: "Successfully deleted the blog" });
    })
    .catch((err) => {
      return res.status(500).json({
        status: 500,
        message: "Failed to delte your blog.",
        error: err.message,
      });
    });
});

server.post("/newNotifications", tokenVerify, (req, res) => {
  let { user_id } = req.body;

  Notification.exists({
    notification_for: user_id,
    seen: false,
    user: { $ne: user_id },
  })
    .then((response) => {
      if (response) {
        return res
          .status(200)
          .json({ status: 200, new_notification_available: true });
      } else {
        return res
          .status(200)
          .json({ status: 200, new_notification_available: false });
      }
    })
    .catch((err) => {
      console.error(err.message);
      return res.status(500).json({
        status: 500,
        error: err.message,
        message: "Failed to see the number of notifications.",
      });
    });
});

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
