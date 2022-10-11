/* eslint-disable global-require */
const config = require('./webpack.common');
const { merge } = require('webpack-merge');
const MiniCssExtractPlugin = require('mini-css-extract-plugin');
const CssMinimizerWebpackPlugin = require('css-minimizer-webpack-plugin');

const base_css = [
  MiniCssExtractPlugin.loader,
  {
    loader: 'css-loader',
    options: {
      importLoaders: 1,
    },
  },
  {
    loader: 'postcss-loader',
    options: {
      postcssOptions: {
        plugins: [require('postcss-preset-env'), require('autoprefixer')()],
      },
    },
  },
];

const plugins = [
  new MiniCssExtractPlugin({
    filename: (data) => (data.chunk.name
        ? 'css/[name]_[contenthash:8].css'
        : 'css/mainChunk_[contenthash:8].css'),
    chunkFilename: (data) => (data.chunk.name
        ? 'css/chunk_[name]_[contenthash:8].css'
        : 'css/chunk_[contenthash:8].css'),
  }),
  new CssMinimizerWebpackPlugin(),
];

if (process.env.Analyse) {
  const BundleAnalyzerPlugin = require('webpack-bundle-analyzer').BundleAnalyzerPlugin;
  plugins.push(new BundleAnalyzerPlugin());
}

if (process.env.Gzip) {
  const CompressionPlugin = require('compression-webpack-plugin');
  plugins.push(
    new CompressionPlugin({
      test: /\.(js|css|json)(\?.*)?$/i,
      threshold: 100 * 1024,
    })
  );
}

module.exports = merge(config, {
  mode: 'production',
  optimization: {
    splitChunks: {
      chunks: 'all',
    },
  },
  performance: {
    hints: false,
  },
  module: {
    rules: [
      {
        oneOf: [
          {
            test: /\.css/i,
            use: base_css,
            // exclude: /node_modules/,
          },
          {
            test: /\.less/,
            use: [...base_css, 'less-loader'],
            exclude: /node_modules/,
          },
        ],
      },
    ],
  },
  plugins,
});
