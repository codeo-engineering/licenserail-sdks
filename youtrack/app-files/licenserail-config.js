// LicenseRail settings for this app. Copy the values from the dashboard (Settings, Products, API keys). None of them is a
// secret: the license key is entered by the customer's administrator in the app settings, never here.
module.exports = {
  apiUrl: 'https://api.licenserail.com',
  /** Your organization id (ten_...). */
  vendor: '__VENDOR_ID__',
  /** The product code from the dashboard. */
  product: '__PRODUCT_CODE__',
  /** The environment's signing key id (for keyless trials). */
  keyId: '__KEY_ID__',
  /** The environment's public key (PEM). */
  publicKeyPem: '__PUBLIC_KEY_PEM__',
  /** Your app's version, reported with activations. */
  appVersion: '1.0.0',
};
