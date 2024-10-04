# CodeSent for Apigee

![CodeSent for Apigee Logo](./assets/logo.png)

**CodeSent for Apigee** is a Visual Studio Code extension that enables Static Application Security Testing (SAST) of your Apigee proxies using the CodeSent service. Enhance the security and quality of your APIs by identifying vulnerabilities early in the development process.

## 📦 Features

- **Automatic Apigee Project Detection:** The extension automatically detects whether the current workspace is an Apigee proxy project.
- **Status Bar Integration:** Quick access to the scan command directly from the VS Code status bar.
- **Secure API Key Management:** Safely store your CodeSent API keys using VS Code's `SecretStorage`.
- **Interactive Notifications:** Receive notifications with actionable buttons to copy the report URL or open it in your default browser.
- **Command Palette Integration:** Execute scan commands via the Command Palette for flexibility.

## 🚀 Installation

### 1. **Via Visual Studio Code Marketplace:**

1. Open Visual Studio Code.
2. Navigate to the Extensions view by clicking on the Extensions icon in the Activity Bar on the side of the window or pressing `Ctrl + Shift + X` (`Cmd + Shift + X` on macOS).
3. Search for `CodeSent for Apigee`.
4. Click **Install** on the extension by **Your Name**.

## 🛠️ Usage

### 1. **Configure API Key:**

Before running scans, you need to set your CodeSent API key.

1. Open the Command Palette by pressing `Ctrl + Shift + P` (`Cmd + Shift + P` on macOS).
2. Type and select `CodeSent: Set API Key`.
3. Enter your **CodeSent API Key** when prompted. The key will be stored securely.

### 2. **Running a Scan:**

#### **Automatic Prompt:**

When you open an Apigee project (identified by the presence of `apiproxy` or `proxies` folders), you'll receive a notification:

- **Message:** "Apigee proxy detected. Do you want to perform a CodeSent scan?"
- **Button:** "Start Scan"

Clicking **Start Scan** will initiate the scanning process.

#### **Manual Scan:**

1. **Via Status Bar:**
   - Click the `Scan Apigee Proxy` button located in the VS Code status bar.

2. **Via Command Palette:**
   - Open the Command Palette (`Ctrl + Shift + P` or `Cmd + Shift + P`).
   - Type and select `CodeSent: Scan Apigee Proxy`.

### 3. **Viewing Results:**

After the scan completes, you'll receive a notification with the following options:

- **Copy Report URL:** Copies the URL of the SAST report to your clipboard.
- **Open in Browser:** Opens the SAST report in your default web browser.

## 🔧 Configuration

The extension provides configurable settings to tailor its behavior to your needs.

### **`codesentScanner.baseUrl`**

- **Type:** `string`
- **Description:** Base URL for the CodeSent SAST Scanner API.
- **Default:** `https://codesent.io/api/scan/v1`

### **Accessing Settings:**

1. Open the Command Palette (`Ctrl + Shift + P` or `Cmd + Shift + P`).
2. Type and select `Preferences: Open Settings (JSON)`.
3. Add or modify the settings as needed.

## 📜 Commands

| Command                               | Description                                      |
| ------------------------------------- | ------------------------------------------------ |
| `codesentScanner.scanProxy`           | Initiate a SAST scan of the Apigee proxy with CodeSent |
| `codesentScanner.setApiKey`           | Set your CodeSent API Key                        |
| `codesentScanner.deleteApiKey`        | Delete your stored CodeSent API Key               |

## 📞 Contact

For any questions, suggestions, or support, please reach out to us at [info@codesent.io](mailto:info@codesent.io).

---
