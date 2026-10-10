"""
W2 Ch1 — Bonus Attack: Selenium + ChromeDriver (Section 1.1, Bonus)

Objective: see the WebDriver-classic side of automation. Selenium talks to
ChromeDriver over the W3C WebDriver protocol; ChromeDriver drives Chrome
over CDP. Selenium Manager (built into Selenium 4) downloads a matching
ChromeDriver and, if needed, Chrome for Testing on first run.

The same identity override as Round 1 is applied through ChromeDriver's
CDP passthrough (driver.execute_cdp_cmd), so the edge layer sees a clean
Chrome. Then compare what Layer 1 reports with the Playwright attacks:
navigator.webdriver is true here too, and current ChromeDriver still
injects its cdc_adoQpoasnfa76pfcZLmcfl_* helper globals into the page.

Expected results (verified with Selenium 4.51 and the Chrome for Testing
build Selenium Manager downloads; the first run downloads ~150 MB):
  - DEFENSE_LEVEL=0  → 200
  - DEFENSE_LEVEL>=1 → 403, "[L1] navigator.webdriver is true ..." and
    "[L1] Automation global found (ChromeDriver (Selenium) helper variable: cdc_...)"

Run the demo site first:
    cd demo_site && DEFENSE_LEVEL=1 python app.py
Then run:
    python attacks/bonus_selenium.py
"""

import json

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

from _common import BASE_URL, CART_PATH, SCRAPE_PATH, chrome_ua, report, require_local


def run(verbose=False):
    require_local()
    options = webdriver.ChromeOptions()
    options.add_argument("--headless=new")
    driver = webdriver.Chrome(options=options)
    try:
        major = driver.capabilities["browserVersion"].split(".")[0]
        full = driver.capabilities["browserVersion"]
        driver.execute_cdp_cmd("Emulation.setUserAgentOverride", {
            "userAgent": chrome_ua(major), "acceptLanguage": "en-US,en", "platform": "Linux x86_64",
            "userAgentMetadata": {
                "brands": [{"brand": "Google Chrome", "version": major}, {"brand": "Chromium", "version": major},
                           {"brand": "Not_A Brand", "version": "8"}],
                "fullVersionList": [{"brand": "Google Chrome", "version": full},
                                    {"brand": "Chromium", "version": full},
                                    {"brand": "Not_A Brand", "version": "8.0.0.0"}],
                "platform": "Linux", "platformVersion": "6.8.0", "architecture": "x86", "model": "",
                "mobile": False, "bitness": "64"}})
        driver.get(f"{BASE_URL}/")
        wait = WebDriverWait(driver, 15)
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, '#status:not([data-state="loading"])')))
        status = driver.find_element(By.ID, "status")
        if verbose:
            keys = driver.execute_script(
                "return Object.keys(document).concat(Object.getOwnPropertyNames(window))"
                ".filter(k => /cdc_/.test(k))")
            print(f"  ChromeDriver variables visible to the page: {json.dumps(keys)}")
        if status.get_attribute("data-state") != "ready":
            return [{"path": SCRAPE_PATH, "status": 403, "reasons": [status.text]},
                    {"path": CART_PATH, "status": None, "reasons": ["never reached the cart"]}]
        driver.find_element(By.CSS_SELECTOR, ".add-to-cart").click()
        wait.until(EC.presence_of_element_located((By.CSS_SELECTOR, '#cart-status:not([data-state="idle"])')))
        cart = driver.find_element(By.ID, "cart-status")
        cart_ok = cart.get_attribute("data-state") == "added"
        return [{"path": SCRAPE_PATH, "status": 200, "reasons": []},
                {"path": CART_PATH, "status": 200 if cart_ok else 403,
                 "reasons": [] if cart_ok else [cart.text]}]
    finally:
        driver.quit()


if __name__ == '__main__':
    report("Bonus: Selenium + ChromeDriver", run(verbose=True))
