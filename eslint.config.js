import { defineConfig } from 'eslint/config';
import globals from 'globals';

export default defineConfig([
    {
        files: ['src/**/*.js'],
        ignores: [
            'node_modules/**',
            'coverage/**',
            'dist/**',
            'build/**'
        ],
        languageOptions: {
            globals: globals.node
        },
        rules: {
            'no-unused-vars': 'warn',
            'no-undef': 'error',
            'no-unreachable': 'error',
            'no-constant-condition': 'warn',
            'no-duplicate-imports': 'error',
            'no-self-assign': 'error',
            'no-unexpected-multiline': 'error'
        }
    },
    {
        files: ['src/webui/public/js/**/*.js'],
        languageOptions: {
            globals: {
                ...globals.browser,
                bootstrap: 'readonly'
            }
        },
        rules: {
            'no-unused-vars': 'warn',
            'no-undef': 'error',
            'no-unreachable': 'error',
            'no-constant-condition': 'warn',
            'no-duplicate-imports': 'error',
            'no-self-assign': 'error',
            'no-unexpected-multiline': 'error'
        }
    }
]);