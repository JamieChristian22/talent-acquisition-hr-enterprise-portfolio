const { defineConfig } = require('@playwright/test');
module.exports = defineConfig({
  testDir:'./tests/browser',
  timeout:30000,
  retries:0,
  reporter:[['list'],['json',{outputFile:'test-results/a11y-results.json'}]],
  use:{baseURL:'http://127.0.0.1:8766',browserName:'chromium',headless:true}
});
