const { DataTypes } = require("sequelize");
const sequelize = require("../db/mysql_connect");

const Language = sequelize.define("Language", {
  language_id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  language_name: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
}, {
  tableName: "LANGUAGE",
  timestamps: false,
});

const languages = [ "Assamese", "Bengali", "Bodo", "Dogri", "English", "Gujarati", "Hindi",
  "Kannada", "Kashmiri", "Konkani", "Maithili", "Malayalam", "Manipuri", "Marathi",
  "Nepali", "Odia", "Punjabi", "Sanskrit", "Santali", "Sindhi", "Tamil", "Telugu",
  "Urdu",
];

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

module.exports = {Language, insertLanguages};
