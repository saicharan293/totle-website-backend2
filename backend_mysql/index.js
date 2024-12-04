const express = require("express");
const app = express();
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const session = require("express-session");
const cors = require("cors");
const sequelize = require("./db/mysql_connect");
const User = require("./models/User");
const Language = require("./models/Language");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const passport = require("passport");
const jwt = require('jsonwebtoken');
const multer = require("multer");
const upload = multer();

// Sync the tables and insert languages after sync
sequelize
  .sync({ alter: true })
  .then(() => {
    console.log("Tables have been synced.");
    insertLanguages();
  })
  .catch((error) => {
    console.error("Error syncing tables:", error);
  });

const googleCors = {
  origin: ["http://localhost:5173","https://www.totle.co"],
  credentials: true,
};

require("dotenv").config();

app.use(cors(googleCors));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    secret: process.env.MY_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:5000/auth/google/callback",
    },
    (accessToken, refreshToken, profile, done) => {
      return done(null, profile);
    }
  )
);

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Languages array
const languages = [
  "Assamese",
  "Bengali",
  "Bodo",
  "Dogri",
  "English",
  "Gujarati",
  "Hindi",
  "Kannada",
  "Kashmiri",
  "Konkani",
  "Maithili",
  "Malayalam",
  "Manipuri",
  "Marathi",
  "Nepali",
  "Odia",
  "Punjabi",
  "Sanskrit",
  "Santali",
  "Sindhi",
  "Tamil",
  "Telugu",
  "Urdu",
];

// Function to insert languages
async function insertLanguages() {
  try {
    const count = await Language.count(); // Check if any records exist
    if (count === 0) {
      // Insert languages if the table is empty
      await Language.bulkCreate(
        languages.map((language) => ({ language_name: language }))
      );
      console.log("Languages successfully inserted into the LANGUAGE table.");
    } else {
      console.log("Languages already exist in the LANGUAGE table.");
    }
  } catch (error) {
    console.error("Error during language insertion:", error);
  }
}

app.get("/", (req, res) => {
  res.send("<a href='/auth/google'>Google</a>");
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  async (req, res) => {
    try {
      const { id: googleId, displayName, emails, name } = req.user;
      let existingUser = await User.findOne({ where: { googleId } });
      if (!existingUser) {
        // If the user does not exist, create a new user record
        const { familyName, givenName } = name;
        const email = emails[0].value; // Google provides emails as an array

        existingUser = await User.create({
          googleId,
          firstName: givenName,
          lastName: familyName,
          email,
          password: null, // Set password as null because user is authenticated via Google
        });
        return res.status(200).json({
          message: "Registration successful. Please set your language preferences.",
          redirectToPreferences: true,
        });
      } else {
        // Check if user already has preferences set
        if (!existingUser.preferredLanguage || existingUser.knownLanguages.length === 0) {
          // If preferences are not set, ask user to set them
          return res.status(200).json({
            message: "User already exists. Please set your language preferences.",
            redirectToPreferences: true,
          });
        }

        // If user exists and has preferences, just send back the user data
        return res.status(200).json({
          message: "User login successful.",
          user: existingUser,
          redirectToPreferences: false, // Preferences already set
        });
      }
    } catch (error) {
      console.error("Error during Google callback: ", error);
      res.status(500).json({ message: "Internal Server Error" });
    }

    return res.status(200).json({
      message: "Google authentication successful",
      user: req.user, // You can send back the user profile info
    });
  }
);

app.get("/logout", (req, res) => {
  req.logOut();
  res.redirect("/");
});

app.get("/auth/google/failure", (req, res) => {
  console.log("fail", req.query);
  res.status(401).json({
    success: false,
    message: "Google authentication failed",
  });
});

// Rate limiting setup to avoid brute force attacks
const signupLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit to 5 requests per window
  message: "Too many requests from this IP, please try again later.",
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit to 5 requests per window
  message: "Too many login attempts from this IP, please try again later.",
});

// Utility function to hash the password
const hashPassword = async (password) => {
  const saltRounds = 10;
  return await bcrypt.hash(password, saltRounds);
};

// Utility function to compare passwords
const comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

// Utility function to generate JWT token
const generateToken = (user) => {
  return jwt.sign(
    { userId: user.id, email: user.email },
    process.env.JWT_SECRET_KEY, // Secret key stored in .env
    { expiresIn: "1h" } // Token expires in 1 hour
  );
};
//this is for my sql

app.post("/signup-user", signupLimiter, async (req, res) => {
  const {
    firstname,
    email,
    // mobile,
    password,
    preferredLanguage,
    lastname,
    knownLanguages,
  } = req.body;

  console.log(preferredLanguage)
  try {
    // Validate required fields
    //if (!username) return res.status(400).json({ error: true, message: "Username is required" });
    if (!firstname)
      return res
        .status(400)
        .json({ error: true, message: "First name is required" });
    if (!email)
      return res
        .status(400)
        .json({ error: true, message: "Email is required" });
    if (!password)
      return res
        .status(400)
        .json({ error: true, message: "Password is required" });
    // if (!mobile)
    //   return res
    //     .status(400)
    //     .json({ error: true, message: "Mobile number is required" });
    if (!preferredLanguage)
      return res
        .status(400)
        .json({ error: true, message: "Preferred language is required" });
    if (!Array.isArray(knownLanguages)) {
      return res
        .status(400)
        .json({ error: true, message: "Known languages must be an array" });
    }

    // Check if user already exists by email or username
    const existingUser = await User.findOne({ where: { email } });

    if (existingUser) {
      return res.status(403).json({
        error: true,
        message: "User with this email exists",
      });
    }

    // Log preferred language for debugging
    console.log("Preferred Language Provided:", preferredLanguage);

    // Fetch the preferredLanguage_id based on the provided language name
    const language = await Language.findOne({
      where: { language_id: preferredLanguage },
    });
    // console.log(language)

    if (!language) {
      return res.status(400).json({
        error: true,
        message: "Preferred language not found",
      });
    }

    // const preferredLanguage_id = language.language_id;

    const validLanguages = await Language.findAll({
      where: { language_id: knownLanguages },
      attributes: ["language_id"],
    });
    console.log(validLanguages.length, knownLanguages.length)
    if (validLanguages.length !== knownLanguages.length) {
      return res
        .status(400)
        .json({ error: true, message: "Some known languages are invalid" });
    }

    const knownLanguageIds = validLanguages.map((lang) => lang.language_id);

    const hashedPassword = await hashPassword(password);

    // Insert new user into the database
    const newUser = await User.create({
      email,
      password: hashedPassword,
      // mobile,
      firstname,
      lastname,
      preferred_language_id: preferredLanguage,
      known_language_ids: knownLanguages,
    });

    if (newUser) {
      return res.status(201).json({
        email,
        // mobile,
        firstname,
        lastname,
        preferredLanguage,
        knownLanguages,
      });
    } else {
      return res
        .status(500)
        .json({ error: true, message: "Failed to create user" });
    }
  } catch (error) {
    console.error("Error during signup: ", error);
    return res.status(500).json({
      error: true,
      message: "Internal Server Error",
    });
  }
});

app.post("/login-user", loginLimiter, async (req, res) => {
  const { email, password } = req.body;

  // Ensure either email or username is provided
  if (!email) {
    return res
      .status(400)
      .json({ error: true, message: "Please enter your email" });
  }

  // Ensure password is provided
  if (!password) {
    return res
      .status(400)
      .json({ error: true, message: "Please enter your password" });
  }

  try {
    // Query to find user by either email or username
    const existingUser = await User.findOne({ where: { email } });

    // If no user is found, return an error
    if (!existingUser) {
      return res
        .status(400)
        .json({ error: true, message: "User doesn't exist, please register" });
    }

    // Validate password using bcrypt
    const match = comparePassword(password, existingUser.password);
    if (!match) {
      return res
        .status(401)
        .json({ error: true, message: "Invalid login credentials" });
    }

    // Generate JWT token for the user
    const token = generateToken(existingUser);

    const user = await User.findOne({
      where: { email }, // Replace with the actual email
      attributes: ['preferred_language_id', 'known_language_ids'],
    });

    const preferredLanguage = await Language.findOne({
      where: { language_id: user.preferred_language_id },
    });

    const knownLanguages = await Language.findAll({
      where: { language_id: user.known_language_ids },
    });

    const userData = {
      firstname: existingUser.firstname,
      lastname: existingUser.lastname,
      email: existingUser.email,
      preferredLanguage,
      knownLanguages// Include known languages, default to empty array
    };

    return res.status(200).json({ message: "Login successful", token, user: userData });
  } catch (error) {
    console.error("Error during login: ", error);
    return res
      .status(500)
      .json({ error: true, message: "Internal Server Error" });
  }
});

// Get list of languages
app.get("/languages", async (req, res) => {
  try {
    const languages = await Language.findAll({
      attributes: ["language_id", "language_name"],
      order: [["language_name", "ASC"]], // Optional: Order languages alphabetically
    });

    res.status(200).json(languages);
  } catch (error) {
    console.error("Error fetching languages:", error);
    res
      .status(500)
      .json({ error: true, message: "Failed to retrieve languages" });
  }
});

app.get("/get-user/:userId", async (req, res) => {
  const { userId } = req.params;

  try {
    // Fetch user details including preferredLanguage_id and known_language_ids
    const user = await User.findOne({
      where: { id: userId },
      attributes: [
        "id",
        "firstname",
        "lastname",
        "email",
        // "mobile",
        "preferred_language_id",
        "known_language_ids",
        "image",
      ],
    });

    if (!user) {
      return res.status(404).json({
        error: true,
        message: "User not found",
      });
    }

    // Fetch the preferred language name based on preferred_language_id
    const preferredLanguage = user.preferred_language_id
      ? await Language.findOne({
          where: { language_id: user.preferred_language_id },
          attributes: ["language_name"],
        })
      : null;

    // Fetch the names of known languages based on known_language_ids
    const knownLanguages = user.known_language_ids
      ? await Language.findAll({
          where: {
            language_id: user.known_language_ids,
          },
          attributes: ["language_name"],
        })
      : [];

    const knownLanguageNames = knownLanguages.map((lang) => lang.language_name);

    // Prepare the response data
    const responseData = {
      id: user.id,
      firstname: user.firstname,
      lastname: user.lastname,
      email: user.email,
      // mobile: user.mobile,
      preferredLanguage: preferredLanguage?.language_name || "Unknown",
      knownLanguages: knownLanguageNames,
      image: user.image || null,
    };

    // Send the response to the frontend
    return res.status(200).json(responseData);
  } catch (error) {
    console.error("Error fetching user information: ", error);
    return res.status(500).json({
      error: true,
      message: "Internal Server Error",
    });
  }
});

app.put("/update-user/:userId", upload.single('image'), async (req, res) => {
  const { userId } = req.params;
  const {
    firstname,
    lastname,
    email,
    mobile,
    preferred_language_id,
    known_language_ids,
  } = req.body;

  try {
    // Check if the user exists
    const user = await User.findOne({ where: { id: userId } });

    if (!user) {
      return res.status(404).json({
        error: true,
        message: "User not found",
      });
    }

    // Update user profile fields if provided in the request body
    if (firstname !== undefined) user.firstname = firstname;
    if (lastname !== undefined) user.lastname = lastname;
    if (email !== undefined) user.email = email;
    if (mobile !== undefined) user.mobile = mobile;
    if (preferred_language_id !== undefined) {
      const preferredLanguage = await Language.findOne({
        where: { language_id: preferred_language_id },
      });

      if (!preferredLanguage) {
        return res.status(400).json({
          error: true,
          message: "Invalid preferred language ID",
        });
      }
      user.preferred_language_id = preferred_language_id;
    }

    if (known_language_ids !== undefined) {
      const knownLanguages = await Language.findAll({
        where: { language_id: known_language_ids },
      });

      if (knownLanguages.length !== known_language_ids.length) {
        return res.status(400).json({
          error: true,
          message: "One or more known language IDs are invalid",
        });
      }
      user.known_language_ids = known_language_ids;
    }
    if (req.file) {
      user.image = req.file.buffer;
    }


    // Save the updated user profile
    await user.save();

    // Fetch updated preferred and known languages for response
    const updatedPreferredLanguage = await Language.findOne({
      where: { language_id: user.preferred_language_id },
      attributes: ["language_name"],
    });

    const updatedKnownLanguages = await Language.findAll({
      where: { language_id: user.known_language_ids },
      attributes: ["language_name"],
    });

    const updatedKnownLanguageNames = updatedKnownLanguages.map(
      (lang) => lang.language_name
    );

    // Prepare the response data
    const responseData = {
      id: user.id,
      firstname: user.firstname,
      lastname: user.lastname,
      email: user.email,
      mobile: user.mobile,
      preferredLanguage: updatedPreferredLanguage?.language_name || "Unknown",
      knownLanguages: updatedKnownLanguageNames,
      image: user.image ? user.image.toString("base64") : null,
    };

    // Send the response
    return res.status(200).json({
      message: "User profile updated successfully",
      data: responseData,
    });
  } catch (error) {
    console.error("Error updating user information: ", error);
    return res.status(500).json({
      error: true,
      message: "Internal Server Error",
    });
  }
});


app.listen(process.env.PORT, () =>
  console.log("server: shuru", process.env.PORT)
);
