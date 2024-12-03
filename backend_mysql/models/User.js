// models/User.js
const { DataTypes } = require("sequelize");
const sequelize = require("../db/mysql_connect");
const Language = require("./Language");

const User = sequelize.define("User", {
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
  },
  googleId: {
    type: DataTypes.STRING,
    allowNull: true,
    unique: true, 
  },
  firstname: {
    type: DataTypes.STRING,
    allowNull: false,
  },
  lastname: {
    type: DataTypes.STRING,
  },
  // mobile: {
  //   type: DataTypes.STRING,
  //   allowNull: true,
  // },
  password: {
    type: DataTypes.STRING,
    allowNull: true,
  },
  bio: {
    type: DataTypes.TEXT,
  },
  preferred_language_id: {
    type: DataTypes.INTEGER,
    references: {
      model: Language,
      key: "language_id",
    },
  },
  known_language_ids: {
    type: DataTypes.JSON,
    allowNull: false,
    defaultValue: [],
  },
  image: {
    type: DataTypes.BLOB("long"),
    allowNull: true,
  },
  concept_mastery: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  accuracy: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  skill_application: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  creativity_expression: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  application_of_knowledge: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  speed: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  problem_solving: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  technical_mastery: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  critical_thinking: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  question_type_proficiency: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  project_completion: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  artistic_process: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  retention: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  exam_strategy: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  adaptability: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  performance_presentation: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  written_verbal_expression: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  syllabus_coverage: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  creativity_innovation: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  feedback_incorporation: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  progress_in_curriculum: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  mock_test_performance: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  certification: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
  portfolio_development: {
    type: DataTypes.TINYINT,
    allowNull: false,
    defaultValue: 0,
    validate: { min: 0, max: 10 },
  },
}, {
  tableName: "USER",
  timestamps: false,
});

// Set up relationship
User.belongsTo(Language, { foreignKey: "preferred_language_id" });

module.exports = User;
