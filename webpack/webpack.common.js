const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const CopyPlugin = require('copy-webpack-plugin');
const DefinePlugin = require('webpack').DefinePlugin;

module.exports = {
  mode: 'none',
  entry: [path.resolve(__dirname, '../web/index.tsx')],
  devServer: {
    hot: true,
    open: false,
    historyApiFallback: true,
    port: 3000,
    static: [
      {
        directory: path.join(__dirname, '../public'),
      }, {
        directory: path.join(__dirname, '../web/assets'),
      }
    ],
    proxy: {
      '/api': {
        target: 'https://www.npmjs.com/',
        pathRewrite: { '/^api/': '' },
        changeOrigin: true,
      },
    },
  },
  output: {
    filename: (data) => (data.chunk.name
        ? 'js/[name]_[contenthash:8].js'
        : 'js/mainChunk_[contenthash:8].js'),
    chunkFilename: (pathData) => (pathData.chunk.name
        ? 'js/chunk_[name]_[contenthash:8].js'
        : 'js/chunk_[contenthash:8].js'),
    path: path.resolve(__dirname, '../dist/web'),
    clean: true,
  },
  cache: {
    type: 'filesystem',
    buildDependencies: {
      config: [__filename],
    },
  },
  resolve: {
    modules: [
      path.resolve(__dirname, '../web'),
      path.resolve(__dirname, '../node_modules'),
    ],
    extensions: ['.tsx', '.ts', '.js', '.json'],
    alias: {
      '@pages': path.resolve(__dirname, '../web/pages'),
    },
  },
  module: {
    rules: [
      {
        oneOf: [
          {
            test: /\.tsx?|jsx?/i,
            use: [
              {
                loader: 'babel-loader',
                options: {
                  cacheDirectory: true, // 启用缓存
                },
              },
            ],
            exclude: /node_modules/,
          },
          {
            test: /\.(png|svg|gif|jpe?g|webp)$/,
            type: 'asset',
            parser: {
              dataUrlCondition: {
                maxSize: 10 * 1024,
              },
            },
            generator: {
              filename: 'images/[contenthash:8][ext]',
            },
            exclude: /node_modules/,
          },
          {
            test: /\.(woff2?|ttf|eot)/i,
            type: 'asset/resource',
            generator: {
              filename: 'fonts/[contenthash:8][ext]',
            },
            exclude: /node_modules/,
          },
        ],
      },
    ],
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: path.resolve(__dirname, '../web/public/index.html'),
    }),
    new CopyPlugin({
      patterns: [
        {
          from: path.resolve(__dirname, '../web/public'), // 复制public下文件
          to: path.resolve(__dirname, '../dist/web'), // 复制到dist目录中
          filter: (source) => !source.includes('index.html') // 忽略index.html
        },
      ],
    }),
    new DefinePlugin({
      'process.env.NODE_ENV': JSON.stringify(process.env.NODE_ENV),
    }),
  ],
};
