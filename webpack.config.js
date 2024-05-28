const path = require('path');
const nodeExternals = require('webpack-node-externals');

module.exports = {
  entry: './src/index.js', // Le point d'entrée de votre application
  output: {
    filename: 'bundle.js', // Le fichier de sortie
    path: path.resolve(__dirname, 'dist'), // Le répertoire de sortie
  },
  target: 'node', // Cible l'environnement Node.js
  mode: 'production', // Mode production pour optimiser la build
  externals: [nodeExternals()], // Exclure les modules de node_modules
  module: {
    rules: [
      {
        test: /\.html$/i, // Fichiers à traiter
        loader: 'html-loader', // Utiliser le html-loader
      },
    ],
  },
};
