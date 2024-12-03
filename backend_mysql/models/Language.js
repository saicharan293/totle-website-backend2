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

module.exports = Language;
