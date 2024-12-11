const { DataTypes } = require("sequelize");
const sequelize = require("../db/mysql_connect");

const Otp = sequelize.define("Otp", {
    email: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
    },
    otp: {
      type: DataTypes.INTEGER,
      allowNull: false,
    },
    expiry: {
      type: DataTypes.DATE,
      allowNull: false,
    },
    isVerified: {
      type: DataTypes.BOOLEAN,
      defaultValue: false,
    },
  });
  

  module.exports = Otp;