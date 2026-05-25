const security = require('eslint-plugin-security');

module.exports = [
  {
    plugins: {
      security: security,
    },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: {
        require: 'readonly',
        process: 'readonly',
        Buffer: 'readonly',
        __dirname: 'readonly',
        console: 'readonly',
        module: 'readonly'
      }
    },
    rules: {
      ...security.configs.recommended.rules,
      'security/detect-object-injection': 'off' // Turn off this specific noisy rule to focus on critical ones
    }
  }
];
