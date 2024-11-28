const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const axios = require("axios"); // For making HTTP requests

const app = express();

app.use(cors());
app.use(bodyParser.json({ limit: "50mb" })); // Adjust the size as needed
app.use(bodyParser.urlencoded({ limit: "50mb", extended: true }));

const PORT = process.env.PORT || 3000;

// MongoDB connection
const dbURI =
  "mongodb+srv://my_database:6mAaP61jyT04DiFU@atlascluster.5hsvgm6.mongodb.net/e_handy_help?retryWrites=true&w=majority&appName=AtlasCluster";

mongoose
  .connect(dbURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB Atlas");
  })
  .catch((error) => {
    console.error("Connection error:", error);
  });

const userSchema = new mongoose.Schema(
  {
    fname: {
      type: String,
      required: true,
    },
    lname: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      required: true,
      unique: true, // Ensure usernames are unique
    },
    password: {
      type: String,
      required: true,
    },
    dateOfBirth: {
      type: Date,
      required: true,
    },
    contact: {
      type: String,
      required: true,
    },
    images: {
      type: [String],
      default: [],
    },
    dataPrivacyConsent: {
      type: Boolean,
      required: true,
    },
    accounts_status: {
      type: String,
      enum: ["pending", "verified", "rejected"],
      default: "pending",
    },
    otp_fp: {
      type: String, // Store the OTP as a string
      default: null, // Default to null if not set
    },
  },
  {
    timestamps: true,
  },
);

const User = mongoose.model("User", userSchema);

// Chat Schema
const chatSchema = new mongoose.Schema({
  booking_id: String,
  handyman_id: String,
  user_id: String,
  sender: String,
  contents: String,
  date_sent: { type: Date, default: Date.now },
});

const Chat = mongoose.model("Chat", chatSchema);

// Notification Schema
const notificationSchema = new mongoose.Schema({
  handymanId: String,
  userId: String,
  notification_content: String,
  date_sent: { type: Date, default: Date.now },
  notif_for: String,
});

const Notification = mongoose.model("Notification", notificationSchema);

const ContactAdminSchema = new mongoose.Schema({
  userId: {
    type: String, // Adjust type if needed, depending on how your IDs are formatted
    required: true,
  },
  subject: {
    type: String,
    required: true,
  },
  details: {
    type: String,
    required: true,
  },
  dateSent: {
    type: Date,
    default: Date.now,
  },
});

const ContactAdmin = mongoose.model("ContactAdmin", ContactAdminSchema);

app.post("/register", async (req, res) => {
  const {
    fname,
    lname,
    username,
    password,
    dateOfBirth,
    contact,
    address,
    images,
    dataPrivacyConsent,
  } = req.body;

  // Validate required fields
  if (
    !fname ||
    !lname ||
    !username ||
    !password ||
    !dateOfBirth ||
    !contact ||
    !dataPrivacyConsent
  ) {
    return res.status(400).send("Missing required fields");
  }

  // Log incoming request data
  console.log("Incoming registration request:", {
    fname,
    lname,
    username,
    dateOfBirth,
    contact,
    address,
    dataPrivacyConsent,
  });

  try {
    // Password hashing
    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("Hashed password:", hashedPassword);

    const user = new User({
      fname,
      lname,
      username,
      password: hashedPassword,
      dateOfBirth,
      contact,
      address,
      images,
      dataPrivacyConsent,
    });

    // Log before saving to the database
    console.log("Attempting to save user to the database:", user);

    // Save the new user to the database
    await user.save();

    // Log successful registration
    console.log(`User registered successfully: ${username}`);

    res.status(201).send("User registered successfully");
  } catch (error) {
    // Log the error for debugging
    console.error("Error registering user:", error.message);
    console.error("Complete error object:", error);

    // Handle specific validation errors
    if (error.name === "ValidationError") {
      return res.status(400).send("Validation error: " + error.message);
    }

    // Send a generic error message back to the client
    res.status(500).send("Error registering user");
  }
});

// Handyman schema and model
// Define the Handyman Schema
const handymanSchema = new mongoose.Schema(
  {
    fname: {
      type: String,
      required: true,
    },
    lname: {
      type: String,
      required: true,
    },
    username: {
      type: String,
      required: true,
      unique: true, // Ensure unique usernames
    },
    password: {
      type: String,
      required: true,
    },
    dateOfBirth: {
      type: Date,
      required: true,
    },
    contact: {
      type: String,
      required: true,
    },
    address: {
      type: String,
      required: true,
    },
    specialization: {
      type: [String], // Array of strings
      required: true,
    },
    idImages: {
      type: [String], // Array of strings for image paths
      default: [],
    },
    certificatesImages: {
      type: [String], // Array of strings for certificate image paths
      default: [],
    },
    dataPrivacyConsent: {
      type: Boolean,
      default: false,
    },
    accounts_status: {
      type: String,
      enum: ["pending", "verified", "rejected", "suspended"], // Possible statuses
      default: "pending", // Default to pending
    },
    otp_fp: {
      type: String, // Store the OTP as a string
      default: null, // Default to null if not set
    },
  },
  {
    timestamps: true, // Automatically create createdAt and updatedAt fields
  },
);

const Handyman = mongoose.model("Handyman", handymanSchema);

app.get("/", (req, res) => {
  res.send("Hello, World!");
});
// Get all verified handymen
app.get("/profiles", async (req, res) => {
  try {
    // Fetch only handymen with account_status set to 'verified'
    const profiles = await Handyman.find({ accounts_status: "verified" });
    res.json(profiles);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});
// Register handyman route
app.post("/register-handyman", async (req, res) => {
  const {
    fname,
    lname,
    username,
    password,
    dateOfBirth,
    contact,
    address,
    specialization,
    idImages,
    certificatesImages,
    dataPrivacyConsent,
  } = req.body;

  // Password hashing
  const hashedPassword = await bcrypt.hash(password, 10);

  const handyman = new Handyman({
    fname,
    lname,
    username,
    password: hashedPassword,
    dateOfBirth,
    contact,
    address,
    specialization,
    idImages,
    certificatesImages,
    dataPrivacyConsent,
  });

  try {
    await handyman.save();
    res.status(201).send("Handyman registered successfully");
  } catch (error) {
    res.status(500).send("Error registering handyman");
  }
});

// Login endpoint
app.post("/login-handyman", async (req, res) => {
  const { username, password } = req.body; // Removed fname and lname from here

  console.log("Login attempt:", { username }); // Log the attempt to login

  try {
    // Check if handyman exists
    const handyman = await Handyman.findOne({ username });
    if (!handyman) {
      console.warn(`Login failed: Invalid username - ${username}`); // Log warning for invalid username
      return res.status(400).json({ message: "Invalid username or password" });
    }

    // Check if password is correct
    const isMatch = await bcrypt.compare(password, handyman.password);
    if (!isMatch) {
      console.warn(`Login failed: Invalid password for username - ${username}`); // Log warning for invalid password
      return res.status(400).json({ message: "Invalid username or password" });
    }

    // Generate JWT token
    const token = jwt.sign({ userId: handyman._id }, "secret_key", {
      expiresIn: "1h",
    });

    // Log successful login
    console.log(
      `Login successful for user: ${username}, Handyman ID: ${handyman._id}`,
    ); // Log successful login

    // Send handyman data along with the token
    res.json({
      token,
      handyman: {
        id: handyman._id,
        fname: handyman.fname,
        lname: handyman.lname,
        username: handyman.username,
        dateOfBirth: handyman.dateOfBirth,
        contact: handyman.contact,
        address: handyman.address,
        specialization: handyman.specialization,
        idImages: handyman.idImages,
        certificatesImages: handyman.certificatesImages,
        dataPrivacyConsent: handyman.dataPrivacyConsent,
        accounts_status: handyman.accounts_status,
      },
    });
  } catch (error) {
    console.error("Error during login:", error); // Log any server error
    res.status(500).json({ message: "Server error" });
  }
});

// Function to format date
const formatDate = (date) => {
  const options = { year: "numeric", month: "long", day: "numeric" };
  return new Date(date).toLocaleDateString(undefined, options); // Format the date to "Month Day, Year"
};

app.get("/requested-profiles", async (req, res) => {
  try {
    // Get handymanId from the query parameters
    const handymanId = req.query.handymanId;

    // Find bookings where handymanId matches and status is requested
    const bookings = await Booking.find({
      handymanId,
      status: "requested",
    }).populate("userId");

    const profiles = await Promise.all(
      bookings.map(async (booking) => {
        const user = await User.findById(booking.userId);
        return {
          bookingId: booking._id,
          userId: user._id,
          name: `${user.fname} ${user.lname}`,
          address: user.address,
          contact: user.contact,
          serviceDetails: booking.serviceDetails,
          dateOfService: formatDate(booking.dateOfService),
          serviceImages: booking.images,
          images: user.images || "default_image.png",
        };
      }),
    );

    res.status(200).json(profiles);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Server error" });
  }
});

// Login endpoint
// Login endpoint
app.post("/login-user", async (req, res) => {
  const { username, password } = req.body;

  try {
    // Log the incoming request body
    console.log("Login request body:", req.body);

    // Check if user exists
    const user = await User.findOne({ username });
    if (!user) {
      console.log("User not found:", username);
      return res.status(400).json({ message: "Invalid username or password" });
    }

    // Log user information
    console.log("User found:", user);

    // Check if password is correct
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      console.log("Password mismatch for user:", username);
      return res.status(400).json({ message: "Invalid username or password" });
    }

    // Log password match success
    console.log("Password match successful for user:", username);

    // Generate JWT token
    const token = jwt.sign({ userId: user._id }, "secret_key", {
      expiresIn: "1h",
    });

    // Log the token generation success
    console.log("JWT token generated for user:", username);

    // Return the token and user data including _id
    res.json({
      token,
      user: {
        _id: user._id,
        username: username,
        fname: user.fname,
        lname: user.lname,
        email: user.email,
        contact: user.contact,
        dateOfBirth: user.dateOfBirth,
        images: user.images,
        accounts_status: user.accounts_status,
      },
    });
  } catch (error) {
    // Log the error with detailed message
    console.error("Server error during login:", error);
    res.status(500).json({ message: "Server error", error: error.message });
  }
});

// Booking Schema
const bookingSchema = new mongoose.Schema({
  userId: String,
  handymanId: String,
  serviceDetails: String,
  dateOfService: Date,
  urgentRequest: Boolean,
  images: [String], // Base64 images
  status: String,
});

const Booking = mongoose.model("Booking", bookingSchema);

// POST route to handle booking requests
app.post("/api/bookings", async (req, res) => {
  const {
    userId,
    handymanId,
    serviceDetails,
    dateOfService,
    urgentRequest,
    images,
    status = "requested",
  } = req.body;

  try {
    // Create a new booking
    const newBooking = new Booking({
      userId,
      handymanId,
      serviceDetails,
      dateOfService,
      urgentRequest,
      images,
      status,
    });

    // Save the booking
    await newBooking.save();

    // Create a notification for the handyman
    const notificationContent = `You have a new booking request for the service: ${serviceDetails}.`;

    const newNotification = new Notification({
      handymanId,
      userId,
      notification_content: notificationContent,
      notif_for: "handyman", // Specify that this notification is for handymen
    });

    // Save the notification
    await newNotification.save();

    // Send response
    res.status(200).json({ message: "Booking request saved successfully" });
  } catch (error) {
    console.error("Error saving booking:", error);
    res.status(500).json({ message: "Error saving booking request" });
  }
});

app.get("/bookings", async (req, res) => {
  const handymanId = req.query.handymanId;
  const status = req.query.status;

  try {
    const bookings = await Booking.find({
      handymanId: handymanId,
      status: status,
    });

    // Prepare an array to hold bookings with user details
    const bookingsWithUserDetails = await Promise.all(
      bookings.map(async (booking) => {
        try {
          // Fetch user data based on userId
          const user = await User.findById(booking.userId).select(
            "fname lname",
          );
          return {
            ...booking._doc, // Spread operator to copy existing booking data
            bookerFirstName: user ? user.fname : "Unknown", // Default to 'Unknown' if user not found
            bookerLastName: user ? user.lname : "Unknown",
          };
        } catch (userErr) {
          console.error("Error fetching user details:", userErr);
          return {
            ...booking._doc,
            bookerFirstName: "Unknown",
            bookerLastName: "Unknown",
          };
        }
      }),
    );

    res.status(200).json(bookingsWithUserDetails);
  } catch (err) {
    console.error("Error fetching bookings:", err); // Log the error details
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

app.get("/bookings-user", async (req, res) => {
  const userId = req.query.userId;
  const status = req.query.status;

  try {
    const bookings = await Booking.find({
      userId: userId,
      status: status,
    });

    // Prepare an array to hold bookings with user details
    const bookingsWithUserDetails = await Promise.all(
      bookings.map(async (booking) => {
        try {
          // Fetch user data based on userId
          const user = await Handyman.findById(booking.handymanId).select(
            "fname lname",
          );
          return {
            ...booking._doc, // Spread operator to copy existing booking data
            bookerFirstName: user ? user.fname : "Unknown", // Default to 'Unknown' if user not found
            bookerLastName: user ? user.lname : "Unknown",
          };
        } catch (userErr) {
          console.error("Error fetching user details:", userErr);
          return {
            ...booking._doc,
            bookerFirstName: "Unknown",
            bookerLastName: "Unknown",
          };
        }
      }),
    );

    res.status(200).json(bookingsWithUserDetails);
  } catch (err) {
    console.error("Error fetching bookings:", err); // Log the error details
    res.status(500).json({ error: "Failed to fetch bookings" });
  }
});

// Accept booking and send chat and notification
app.post("/accept-booking", async (req, res) => {
  const {
    handymanId,
    userId,
    bookingId,
    serviceDetails,
    name,
    contact,
    address,
    dateOfService,
  } = req.body;

  try {
    // Save auto-generated chat message
    const chatContent = `This is an auto-generated chat. Hi ${name}, I have accepted your booking for ${serviceDetails}. Please confirm if the following details are correct:\nName: ${name},\nContact: ${contact},\nAddress: ${address},\nBooking Date: ${dateOfService}\nThank you!`;

    const newChat = new Chat({
      booking_id: bookingId,
      handyman_id: handymanId,
      sender: "handy",
      user_id: userId,
      contents: chatContent,
    });
    await newChat.save();

    // Save notification
    const notification = new Notification({
      handymanId,
      userId,
      notification_content: "Accepted your booking!",
      notif_for: "user",
    });
    await notification.save();

    // Update booking status based on bookingId
    await Booking.findOneAndUpdate(
      { _id: bookingId }, // Use bookingId to find the booking
      { status: "accepted" },
      { new: true },
    );

    res
      .status(200)
      .json({ message: "Booking accepted, chat and notification sent." });
  } catch (error) {
    console.error(error); // Log error for debugging
    res.status(500).json({ error: "Failed to accept booking." });
  }
});

// Decline booking and send notification
app.post("/decline-booking", async (req, res) => {
  const { handymanId, userId, bookingId } = req.body; // Accept bookingId

  try {
    // Save notification
    const notification = new Notification({
      handymanId,
      userId,
      notification_content: "Your booking has been declined!",
    });
    await notification.save();

    // Update booking status based on bookingId
    await Booking.findOneAndUpdate(
      { _id: bookingId }, // Use bookingId to find the booking
      { status: "declined" },
      { new: true },
    );

    res.status(200).json({ message: "Booking declined, notification sent." });
  } catch (error) {
    console.error(error); // Log error for debugging
    res.status(500).json({ error: "Failed to decline booking." });
  }
});

const ObjectId = mongoose.Types.ObjectId; // Mongoose's ObjectId constructor

// Endpoint to fetch messages grouped by booking_id
app.get("/api/messages", async (req, res) => {
  try {
    // Extract handymanId from query parameters
    const handymanId = req.query.handymanId;
    console.log(handymanId);
    // Validate handymanId
    if (!handymanId) {
      return res.status(400).json({ message: "handymanId is required" });
    }

    // Ensure handymanId is a valid ObjectId
    if (!ObjectId.isValid(handymanId)) {
      return res.status(400).json({ message: "Invalid handymanId format" });
    }

    const messages = await Chat.aggregate([
      {
        $match: {
          handyman_id: handymanId, // Filter by handymanId
        },
      },
      {
        $group: {
          _id: {
            user_id: { $toObjectId: "$user_id" }, // Convert user_id to ObjectId
            handyman_id: "$handyman_id",
            booking_id: "$booking_id",
          },
          last_message: { $last: "$contents" },
          date_sent: { $last: "$date_sent" },
        },
      },
      {
        $lookup: {
          from: "users",
          localField: "_id.user_id",
          foreignField: "_id", // Assuming user_id in users collection is an ObjectId
          as: "user_details",
        },
      },
      {
        $unwind: {
          path: "$user_details",
          preserveNullAndEmptyArrays: true, // Preserve documents with no user details
        },
      },
      {
        $project: {
          user_id: "$_id.user_id",
          handyman_id: "$_id.handyman_id",
          booking_id: "$_id.booking_id",
          last_message: { $substr: ["$last_message", 0, 25] }, // Adjust length if necessary
          userFirstName: "$user_details.fname",
          userLastName: "$user_details.lname",
          date_sent: "$date_sent",
        },
      },
      { $sort: { date_sent: -1 } }, // Sort messages by date_sent in descending order
    ]);

    // Handle empty results
    if (!messages.length) {
      return res.status(404).json({ message: "No messages found" });
    }

    res.json(messages);
  } catch (error) {
    console.error("Error fetching messages:", error); // Log the error for debugging
    res.status(500).json({ error: "Error fetching messages" });
  }
});


