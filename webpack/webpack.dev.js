const config = require('./webpack.common');
const { merge } = require('webpack-merge');
const webpack = require('webpack');

module.exports = merge(config, {
  mode: 'development',
  module: {
    rules: [
      {
        oneOf: [
          {
            test: /\.css/i,
            use: ['style-loader', 'css-loader'],
            // exclude: /node_modules/,
          },
          {
            test: /\.less/,
            use: ['style-loader', 'css-loader'],
            exclude: /node_modules/,
          },
        ],
      },
    ],
  },
  devtool: 'eval-cheap-module-source-map',
  plugins: [new webpack.HotModuleReplacementPlugin()],
});
