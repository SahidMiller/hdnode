const path = require('path')
const isDevEnv = process.env.NODE_ENV === "development"

module.exports = {
  entry: {
    hdnode: path.resolve(__dirname, './src/index.js')
  },
  target: "node",
  output: {
    path: path.resolve(__dirname, "./dist"),
    filename: "[name].js",
    libraryTarget: "commonjs",
  },
  mode: process.env.NODE_ENV,
  watch: isDevEnv,
  devtool: "source-map",
  stats: {
    warnings: isDevEnv,
  }
}