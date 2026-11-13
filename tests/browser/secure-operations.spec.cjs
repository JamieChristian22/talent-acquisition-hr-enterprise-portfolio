const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const fs = require('node:fs');
const path = require('node:path');

function users(){
  if(!process.env.TAHR_TEST_LOGIN_FILE) throw new Error('Ephemeral login file not configured');
  return JSON.parse(fs.readFileSync(process.env.TAHR_TEST_LOGIN_FILE, 'utf-8'));
}

async function audit(page,label){
  const results=await new AxeBuilder({page}).withTags(['wcag2a','wcag2aa','wcag21aa','wcag22aa']).analyze();
  expect(results.violations, `${label}: ${JSON.stringify(results.violations,null,2)}`).toEqual([]);
}

async function login(page,username,password){
  await page.goto('/');
  await page.getByLabel('Username').fill(username);
  await page.getByLabel('Password').fill(password);
  await page.getByRole('button',{name:'Sign in securely'}).click();
  await expect(page.getByRole('heading',{name:'Your workspace'})).toBeVisible();
}

test('Login page automated WCAG scan and keyboard navigation',async({page})=>{
  await page.goto('/');
  await audit(page,'login');
  await page.keyboard.press('Tab');
  await expect(page.locator('a.skip')).toBeFocused();
  await page.keyboard.press('Enter');
  await expect(page.locator('main')).toBeVisible();
  await expect(page.locator('#login-form input')).toHaveCount(2);
});

test('Admin authenticated flow, visible roles and axe scan',async({page})=>{
  const credentials=users();
  await login(page,credentials.admin.username,credentials.admin.password);
  await audit(page,'authenticated admin');
  await expect(page.getByRole('heading',{name:'Submit a requisition'})).toBeVisible();
  await page.getByLabel('Job title').fill('Accessibility Operations Analyst');
  await page.getByRole('button',{name:'Submit for approval'}).click();
  await expect(page.getByRole('cell',{name:'Accessibility Operations Analyst'})).toBeVisible();
  await page.getByRole('button',{name:'Sign out'}).click();
  await expect(page.getByRole('heading',{name:'Sign in'})).toBeVisible();
});

test('Analyst never sees detailed applications or privileged controls',async({page})=>{
  const credentials=users();
  await login(page,credentials.analyst.username,credentials.analyst.password);
  await expect(page.getByRole('heading',{name:'Recruiting metrics'})).toBeVisible();
  await expect(page.getByRole('heading',{name:'Submit a requisition'})).toBeHidden();
  await expect(page.getByRole('heading',{name:'Approved and pending requisitions'})).toBeHidden();
  await audit(page,'authenticated analyst');
});

test('Mobile 375px axe scan and horizontal-overflow check',async({page})=>{
  await page.setViewportSize({width:375,height:812});
  await page.goto('/');
  await audit(page,'mobile login');
  const overflow=await page.evaluate(()=>document.documentElement.scrollWidth>window.innerWidth+1);
  expect(overflow).toBeFalsy();
});
