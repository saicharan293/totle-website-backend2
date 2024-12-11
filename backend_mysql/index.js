const express = require("express");
const app = express();
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const session = require("express-session");
const cors = require("cors");
const sequelize = require("./db/mysql_connect");
const User = require("./models/User");
const {Language,insertLanguages} = require("./models/Language");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const passport = require("passport");
const Otp = require("./models/Otp");
const nodemailer = require("nodemailer");
const jwt = require('jsonwebtoken');
const multer = require("multer");
const upload = multer();

// Sync the tables and insert languages after sync
sequelize
  .sync() // Sync the database
  .then(async () => {
    await insertLanguages(); 
  })
  .catch((error) => {
    console.error("Error syncing tables:", error);
  });

const googleCors = {
  origin: ["http://localhost:3000","https://www.totle.co"],
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
  console.log('hash started')
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


app.get('/insert-languages', async (req, res) => {
  try {
    await insertLanguages();  // Call the insertLanguages function from your model
    // console.log('entered')
    res.status(200).json({ message: 'Languages inserted successfully.' });
  } catch (error) {
    console.error('Error inserting languages:', error);
    res.status(500).json({ message: 'Error inserting languages' });
  }
});

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

  console.log(email)
  try {
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
    // console.log("Preferred Language Provided:", preferredLanguage);

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

    if (validLanguages.length !== knownLanguages.length) {
      return res
        .status(400)
        .json({ error: true, message: "Some known languages are invalid" });
    }

    const result= await sendOTP(email);
    if (result.error) {
      return res.status(400).json({ error: true, message: result.message });
    } else {
      return res.status(200).json({ message: result.message });
    }
    
  } catch (error) {
    console.error("Error during signup: ", error);
    return res.status(500).json({
      error: true,
      message: "Internal Server Error",
    });
  }
});

app.post('/verify-signup', async(req,res)=>{
  const {email, otp, firstname, password, preferredLanguage, lastname, knownLanguages} = req.body;
  try {
    const result = await verifyOtp(email, otp);
    if (result.error) {
      return res.status(400).json({ error: true, message: result.message });
    } 
    const hashedPassword = await hashPassword(password);
    const newUser = await User.create({
      email,
      password: hashedPassword,
      firstname,
      lastname,
      preferred_language_id: preferredLanguage,
      known_language_ids: knownLanguages,
    });
    return res.status(201).json({ error: false, message: "User created successfully" });
  } catch (error) {
    return res.status(400).json({ error: true, message: " Internal server error"})
  }
})

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
      attributes: ["id","preferred_language_id", "known_language_ids"],
    });

    const preferredLanguage = await Language.findOne({
      where: { language_id: user.preferred_language_id },
    });

    const knownLanguages = await Language.findAll({
      where: { language_id: user.known_language_ids },
    });

    const userData = {
      userid:user.id,
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


// Function to send OTP email using Gmail SMTP with App Password
async function sendOtpEmail(toEmail, otp) {
  try {
    // Configure the transporter with Gmail SMTP and App Password
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.GMAIL_EMAIL, // Your Gmail address
        pass: process.env.GMAIL_APP_PASSWORD, // App Password
      },
    });

    // Email content
    const mailOptions = {
      from: `"TOTLE" <${process.env.GMAIL_EMAIL}>`,
      to: toEmail,
      subject: "Your OTP for Recovery password",
      text: `Your OTP for registration is: ${otp}`, // Plain text body
    };

    // Send the email
    await transporter.sendMail(mailOptions);
    console.log("OTP sent successfully:", otp);
  } catch (error) {
    console.error("Error sending OTP:", error);
    throw new Error("Failed to send OTP");
  }
}

async function sendOTP(email){

  try {
    const existingOtp = await Otp.findOne({ where: { email } });

    if (existingOtp) {
      const timeRemaining = new Date(existingOtp.expiry) - new Date();
      if (timeRemaining > 0) {
        const secondsRemaining = Math.ceil(timeRemaining / 1000); // Convert to seconds
        return res.status(400).json({
          error: true,
          message: `OTP already sent. Please wait ${secondsRemaining} seconds before requesting a new OTP.`,
        });
      }

      // Update the existing OTP record
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 1-minute expiry

      await existingOtp.update({ otp, expiry: otpExpiry, isVerified: false });

      await sendOtpEmail(email, otp); // Send OTP email
      return {
        message: "OTP sent to your email. Please verify within 1 minute.",
      };
    }

    // No existing OTP, create a new record
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpExpiry = new Date(Date.now() + 5 * 60 * 1000); // 5-minute expiry

    await Otp.create({ email, otp, expiry: otpExpiry, isVerified: false });

    await sendOtpEmail(email, otp); // Send OTP email
    return {
      message: "OTP sent to your email. Please verify within 1 minute.",
    };
  } catch (error) {
    console.error("Error sending OTP:", error);
    return { error: true, message: "Internal Server Error" };
  }
}
// Route to send OTP for forgot password
app.post("/send-otp", async (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.status(400).json({ error: true, message: "Email is required" });
  }
  const result= await sendOTP(email);
  if (result.error) {
    return res.status(400).json({ error: true, message: result.message });
  } else {
    return res.status(200).json({ message: result.message });
  }
});

async function verifyOtp(email,otp){
  try {
    const otpRecord = await Otp.findOne({
      where: { email, otp, isVerified: false },
    });

    if (!otpRecord) {
      return { error: true, message: "Invalid OTP" };
    }

    const currentTime = new Date();
    if (currentTime > otpRecord.expiry) {
      return { error: true, message: "OTP has expired" };
    }

    // Mark OTP as verified
    otpRecord.isVerified = true;
    await otpRecord.save();
    return {
      error: false,
      message: "OTP verified successfully. You can proceed",
    };
  } catch (error) {
    console.error("Error verifying OTP:", error);
    return { error: true, message: "Internal Server Error" };
  }
}

// Route to verify OTP
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) {
    return res.status(400).json({ error: true, message: "Email and OTP are required" });
  }

  const result = await verifyOtp(email, otp);
  if (result.error) {
    return res.status(400).json({ error: true, message: result.message });
  } else {
    return res.status(200).json({error: false, message: result.message });
  }

});

// Reset Password Endpoint
app.post('/reset-password', async (req, res) => {
  const { email, newPassword } = req.body;
  console.log(email)

  if (!email || !newPassword) {
    return res.status(400).json({ error: true, message: 'Email and new password are required' });
  }

  try {
    // Find the user by email
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({ error: true, message: 'User not found' });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update the user's password in the database
    user.password = hashedPassword;
    await user.save();

    return res.status(200).json({ message: 'Password has been reset successfully' });
  } catch (error) {
    console.error('Error resetting password:', error);
    return res.status(500).json({ error: true, message: 'Internal Server Error' });
  }
});



app.listen(process.env.PORT, () =>
  console.log("server: shuru", process.env.PORT)
);
