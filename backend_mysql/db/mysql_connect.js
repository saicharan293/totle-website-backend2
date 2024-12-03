const { Sequelize } = require("sequelize");
require("dotenv").config();
const databaseName = "totle_dbv2";

// Helper function to connect to the MySQL server without specifying a database
const rootSequelize = new Sequelize({
  host: "localhost",
  dialect: "mysql",
  username: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  logging: false,
});

// Main Sequelize instance for the target database
const sequelize = new Sequelize(databaseName, process.env.DB_USER, process.env.DB_PASSWORD, {
  host: "localhost",
  dialect: "mysql",
  logging: false,
});

async function initializeDatabase() {
  try {
    // Check if the database exists and create it if necessary
    await rootSequelize.query(`CREATE DATABASE IF NOT EXISTS \`${databaseName}\`;`);
    console.log(`Database '${databaseName}' is ready.`);
    
    // Close root connection after database check
    await rootSequelize.close();

    // Authenticate with the main Sequelize instance
    await sequelize.authenticate();
    console.log("Connected to the database successfully.");
    await sequelize.sync({alter: true})
  } catch (error) {
    console.error("Error during database initialization:", error);
  }
}

// Initialize the database and connect
initializeDatabase();

module.exports = sequelize;
